use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Instant,
};

use anyhow::{Context, Result, ensure};
use http::{HeaderMap, Method, Uri, Version};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug)]
pub struct CaptureLimits {
    pub sessions: usize,
    pub body_bytes: usize,
    pub total_body_bytes: usize,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            sessions: 1_000,
            body_bytes: 1024 * 1024,
            total_body_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

pub fn headers_from(map: &HeaderMap) -> Vec<Header> {
    map.iter()
        .map(|(name, value)| Header {
            name: name.to_string(),
            value: match std::str::from_utf8(value.as_bytes()) {
                Ok(text) => text.to_owned(),
                Err(_) => value.as_bytes().iter().map(|&b| char::from(b)).collect(),
            },
        })
        .collect()
}

pub fn header<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

pub fn protocol_name(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/?",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Request,
    Response,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    Http,
    Tunnel,
    WebSocket,
}

#[derive(Clone, Debug, Default)]
pub struct CapturedBody {
    pub data: Vec<u8>,
    pub total_bytes: u64,
    pub complete: bool,
    pub trailers: Vec<Header>,
}

impl CapturedBody {
    pub fn truncated(&self) -> bool {
        self.data.len() as u64 != self.total_bytes
    }
}

#[derive(Clone, Debug)]
pub struct ArchiveInfo {
    pub har: Option<crate::har_import::Evidence>,
    pub original_id: u64,
    pub bit_flags: Option<u64>,
    pub flags: BTreeMap<String, String>,
    pub timers: BTreeMap<String, String>,
    pub notes: Vec<String>,
    pub complete: bool,
}

#[derive(Clone, Debug)]
pub struct Session {
    pub id: u64,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub protocol: String,
    pub response_protocol: String,
    pub client: String,
    pub kind: SessionKind,
    pub started_at: Option<OffsetDateTime>,
    pub started: Instant,
    pub duration_ms: Option<u64>,
    pub headers_ms: Option<u64>,
    pub status: Option<u16>,
    pub request_headers: Vec<Header>,
    pub response_headers: Vec<Header>,
    pub request: CapturedBody,
    pub response: CapturedBody,
    pub error: Option<String>,
    pub archive: Option<ArchiveInfo>,
    pub(crate) snapshot_elapsed_ms: Option<u64>,
}

impl Session {
    pub fn elapsed_ms(&self) -> Option<u64> {
        if self.archive.is_some() {
            return self.duration_ms;
        }
        Some(
            self.duration_ms
                .or(self.snapshot_elapsed_ms)
                .unwrap_or_else(|| self.started.elapsed().as_millis() as u64),
        )
    }

    pub fn is_settled(&self) -> bool {
        self.archive.is_some() || self.duration_ms.is_some()
    }

    pub fn capture_complete(&self) -> bool {
        self.archive
            .as_ref()
            .map_or(self.duration_ms.is_some(), |archive| archive.complete)
    }

    fn frozen(&self) -> Self {
        let elapsed = self.elapsed_ms();
        let mut snapshot = self.clone();
        snapshot.snapshot_elapsed_ms = elapsed;
        snapshot
    }

    pub fn body(&self, side: Side) -> &CapturedBody {
        match side {
            Side::Request => &self.request,
            Side::Response => &self.response,
        }
    }

    fn body_mut(&mut self, side: Side) -> &mut CapturedBody {
        match side {
            Side::Request => &mut self.request,
            Side::Response => &mut self.response,
        }
    }

    pub fn headers(&self, side: Side) -> &[Header] {
        match side {
            Side::Request => &self.request_headers,
            Side::Response => &self.response_headers,
        }
    }

    pub fn summary(&self) -> SessionSummary {
        SessionSummary {
            har: self.archive.as_ref().and_then(|a| a.har.as_ref()).map(|e| crate::har_import::Summary {
                source: "HAR", time: e.time, request: e.request.clone(), response: e.response.clone(),
                request_retained_bytes: self.request.data.len(), response_retained_bytes: self.response.data.len(),
                request_available_bytes: self.request.total_bytes, response_available_bytes: self.response.total_bytes,
            }),
            id: self.id,
            method: self.method.clone(),
            url: self.url.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            protocol: self.protocol.clone(),
            status: self.status,
            kind: self.kind,
            content_type: header(&self.response_headers, "content-type")
                .or_else(|| self.archive.as_ref().and_then(|a| a.har.as_ref()).map(|h| h.response.mime.as_str()))
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .to_owned(),
            bytes: self.response.total_bytes,
            elapsed_ms: self.elapsed_ms(),
            complete: self.is_settled(),
            failed: self.error.is_some(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SessionSummary {
    pub har: Option<crate::har_import::Summary>,
    pub id: u64,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub protocol: String,
    pub status: Option<u16>,
    pub kind: SessionKind,
    pub content_type: String,
    pub bytes: u64,
    pub elapsed_ms: Option<u64>,
    pub complete: bool,
    pub failed: bool,
}

impl SessionSummary {
    pub fn is_error(&self) -> bool {
        self.failed || self.status.is_some_and(|status| status >= 400)
    }

    pub fn is_https(&self) -> bool {
        self.url.starts_with("https://") || self.kind == SessionKind::Tunnel
    }
}

#[derive(Clone, Debug)]
pub struct Notice {
    pub time: OffsetDateTime,
    pub message: String,
}

pub struct Snapshot {
    pub revision: u64,
    pub sessions: Vec<SessionSummary>,
    pub retained_bytes: usize,
    pub evicted: u64,
    pub body_limit_hit: bool,
}

#[derive(Default)]
struct State {
    sessions: BTreeMap<u64, Session>,
    retained_bytes: usize,
    evicted: u64,
    body_limit_hit: bool,
    notices: VecDeque<Notice>,
}

pub struct CaptureStore {
    state: Mutex<State>,
    limits: CaptureLimits,
    next_id: AtomicU64,
    revision: AtomicU64,
    recording: AtomicBool,
}

impl Default for CaptureStore {
    fn default() -> Self {
        Self {
            state: Mutex::new(State::default()),
            limits: CaptureLimits::default(),
            next_id: AtomicU64::new(1),
            revision: AtomicU64::new(1),
            recording: AtomicBool::new(true),
        }
    }
}

impl CaptureStore {
    pub fn with_limits(limits: CaptureLimits) -> Result<Self> {
        ensure!(limits.sessions > 0, "Session limit must be positive");
        ensure!(limits.body_bytes > 0, "Body limit must be positive");
        ensure!(
            limits.total_body_bytes >= limits.body_bytes,
            "Total body budget must be at least the per-body limit"
        );
        Ok(Self {
            limits,
            ..Self::default()
        })
    }

    pub fn limits(&self) -> CaptureLimits {
        self.limits
    }

    pub fn recording(&self) -> bool {
        self.recording.load(Ordering::Relaxed)
    }

    pub fn set_recording(&self, enabled: bool) {
        self.recording.store(enabled, Ordering::Relaxed);
        self.changed();
    }

    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }

    fn changed(&self) {
        self.revision.fetch_add(1, Ordering::Relaxed);
    }

    pub fn begin(
        &self,
        method: &Method,
        uri: &Uri,
        version: Version,
        headers: &HeaderMap,
        client: SocketAddr,
    ) -> Option<u64> {
        if !self.recording() {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let tunnel = method == Method::CONNECT;
        let session = Session {
            id,
            method: method.to_string(),
            url: uri.to_string(),
            host: uri.host().unwrap_or("").to_owned(),
            path: if tunnel {
                uri.to_string()
            } else {
                uri.path_and_query()
                    .map_or("/", |path| path.as_str())
                    .to_owned()
            },
            protocol: protocol_name(version).to_owned(),
            response_protocol: String::new(),
            client: client.to_string(),
            kind: if tunnel {
                SessionKind::Tunnel
            } else {
                SessionKind::Http
            },
            started_at: Some(OffsetDateTime::now_utc()),
            started: Instant::now(),
            duration_ms: None,
            headers_ms: None,
            status: None,
            request_headers: headers_from(headers),
            response_headers: Vec::new(),
            request: CapturedBody::default(),
            response: CapturedBody::default(),
            error: None,
            archive: None,
            snapshot_elapsed_ms: None,
        };
        let mut state = self.state.lock();
        while state.sessions.len() >= self.limits.sessions {
            if let Some((_, old)) = state.sessions.pop_first() {
                state.retained_bytes -= old.request.data.len() + old.response.data.len();
                state.evicted += 1;
            }
        }
        state.sessions.insert(id, session);
        self.changed();
        Some(id)
    }

    pub fn response(&self, id: Option<u64>, status: u16, version: Version, headers: &HeaderMap) {
        self.update(id, |session| {
            session.status = Some(status);
            session.response_protocol = protocol_name(version).to_owned();
            session.response_headers = headers_from(headers);
            session.headers_ms = Some(session.started.elapsed().as_millis() as u64);
        });
    }

    pub fn set_kind(&self, id: Option<u64>, kind: SessionKind) {
        self.update(id, |session| session.kind = kind);
    }

    pub fn append(&self, id: Option<u64>, side: Side, bytes: &[u8]) {
        let Some(id) = id else { return };
        let mut state = self.state.lock();
        let budget = self.limits.total_body_bytes - state.retained_bytes;
        if let Some(session) = state.sessions.get_mut(&id) {
            let body = session.body_mut(side);
            let count = bytes
                .len()
                .min(self.limits.body_bytes - body.data.len())
                .min(budget);
            body.total_bytes += bytes.len() as u64;
            body.data.extend_from_slice(&bytes[..count]);
            state.retained_bytes += count;
            state.body_limit_hit |= count < bytes.len();
            self.changed();
        }
    }

    pub fn trailers(&self, id: Option<u64>, side: Side, trailers: &HeaderMap) {
        self.update(id, |session| {
            session.body_mut(side).trailers = headers_from(trailers);
        });
    }

    pub fn complete_body(&self, id: Option<u64>, side: Side) {
        self.update(id, |session| {
            session.body_mut(side).complete = true;
            if side == Side::Response {
                session.duration_ms = Some(session.started.elapsed().as_millis() as u64);
            }
        });
    }

    pub fn complete_tunnel(&self, id: Option<u64>, sent: u64, received: u64) {
        self.update(id, |session| {
            session.request.total_bytes = sent;
            session.response.total_bytes = received;
            session.request.complete = true;
            session.response.complete = true;
            session.duration_ms = Some(session.started.elapsed().as_millis() as u64);
        });
    }

    pub fn count_tunnel_bytes(&self, id: Option<u64>, side: Side, count: usize) {
        self.update(id, |session| {
            session.body_mut(side).total_bytes += count as u64
        });
    }

    pub fn error(&self, id: Option<u64>, message: impl AsRef<str>) {
        let message: String = message.as_ref().chars().take(2_048).collect();
        self.update(id, |session| {
            if session.error.is_none() {
                session.error = Some(message.clone());
            }
            session.duration_ms = Some(session.started.elapsed().as_millis() as u64);
        });
        self.notice(match id {
            Some(id) => format!("#{id}: {message}"),
            None => message,
        });
    }

    fn update(&self, id: Option<u64>, f: impl FnOnce(&mut Session)) {
        let Some(id) = id else { return };
        if let Some(session) = self.state.lock().sessions.get_mut(&id) {
            f(session);
            self.changed();
        }
    }

    #[cfg(windows)]
    pub(crate) fn set_demo_timing(&self, id: Option<u64>, elapsed: u64) {
        self.update(id, |session| {
            session.started = Instant::now() - std::time::Duration::from_millis(elapsed);
            session.duration_ms = Some(elapsed);
            session.headers_ms = Some(elapsed.saturating_sub(5));
        });
    }

    pub fn notice(&self, message: impl AsRef<str>) {
        let mut state = self.state.lock();
        if state.notices.len() == 100 {
            state.notices.pop_front();
        }
        state.notices.push_back(Notice {
            time: OffsetDateTime::now_utc(),
            message: message.as_ref().chars().take(2_048).collect(),
        });
        self.changed();
    }

    pub fn notices(&self) -> Vec<Notice> {
        self.state.lock().notices.iter().cloned().collect()
    }

    pub fn get(&self, id: u64) -> Option<Session> {
        self.state.lock().sessions.get(&id).map(Session::frozen)
    }

    pub fn sessions(&self, ids: &[u64]) -> Vec<Session> {
        let state = self.state.lock();
        ids.iter()
            .filter_map(|id| state.sessions.get(id).map(Session::frozen))
            .collect()
    }

    pub fn all_sessions(&self) -> Vec<Session> {
        self.state
            .lock()
            .sessions
            .values()
            .map(Session::frozen)
            .collect()
    }

    pub fn snapshot(&self) -> Snapshot {
        let state = self.state.lock();
        Snapshot {
            revision: self.revision(),
            sessions: state.sessions.values().map(Session::summary).collect(),
            retained_bytes: state.retained_bytes,
            evicted: state.evicted,
            body_limit_hit: state.body_limit_hit,
        }
    }

    pub fn clear(&self) {
        let mut state = self.state.lock();
        state.sessions.clear();
        state.retained_bytes = 0;
        state.evicted = 0;
        state.body_limit_hit = false;
        self.changed();
    }

    pub fn replace_from_archive(&self, mut sessions: Vec<Session>) -> Result<()> {
        ensure!(
            sessions.len() <= self.limits.sessions,
            "Archive exceeds the session retention limit"
        );
        let mut retained = 0usize;
        let mut truncated = false;
        for session in &sessions {
            ensure!(
                session.archive.is_some(),
                "Only archive snapshots can be imported"
            );
            for body in [&session.request, &session.response] {
                ensure!(
                    body.data.len() <= self.limits.body_bytes,
                    "Archive body exceeds the capture limit"
                );
                ensure!(
                    body.total_bytes >= body.data.len() as u64,
                    "Archive body byte counts are inconsistent"
                );
                retained = retained
                    .checked_add(body.data.len())
                    .context("Archive byte count overflow")?;
                truncated |= body.truncated();
            }
        }
        ensure!(
            retained <= self.limits.total_body_bytes,
            "Archive exceeds the retained body budget"
        );
        let count = u64::try_from(sessions.len())?;
        let mut state = self.state.lock();
        let first = self
            .next_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
                id.checked_add(count)
            })
            .map_err(|_| anyhow::anyhow!("Session ID space exhausted"))?;
        for (offset, session) in sessions.iter_mut().enumerate() {
            session.id = first + offset as u64;
        }
        state.sessions = sessions
            .into_iter()
            .map(|session| (session.id, session))
            .collect();
        state.retained_bytes = retained;
        state.evicted = 0;
        state.body_limit_hit = truncated;
        state.notices.clear();
        self.changed();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn begin(store: &CaptureStore) -> Option<u64> {
        store.begin(
            &Method::GET,
            &"https://example.test/a".parse().unwrap(),
            Version::HTTP_11,
            &HeaderMap::new(),
            "127.0.0.1:1234".parse().unwrap(),
        )
    }

    #[test]
    fn capture_limits_do_not_change_transferred_byte_counts() {
        let store = CaptureStore::with_limits(CaptureLimits {
            sessions: 2,
            body_bytes: 4,
            total_body_bytes: 6,
        })
        .unwrap();
        let id = begin(&store);
        store.append(id, Side::Request, b"123456");
        store.append(id, Side::Response, b"abcdef");
        let session = store.get(id.unwrap()).unwrap();
        assert_eq!(session.request.data, b"1234");
        assert_eq!(session.response.data, b"ab");
        assert_eq!(session.response.total_bytes, 6);
        assert!(session.response.truncated());
        assert_eq!(store.snapshot().retained_bytes, 6);
    }

    #[test]
    fn eviction_releases_budget_and_never_reuses_ids() {
        let store = CaptureStore::with_limits(CaptureLimits {
            sessions: 1,
            body_bytes: 4,
            total_body_bytes: 4,
        })
        .unwrap();
        let first = begin(&store);
        store.append(first, Side::Response, b"full");
        let second = begin(&store);
        assert_ne!(first, second);
        assert!(store.get(first.unwrap()).is_none());
        assert_eq!(store.snapshot().retained_bytes, 0);
        store.append(first, Side::Response, b"late");
        assert_eq!(store.snapshot().retained_bytes, 0);
        assert_eq!(store.snapshot().evicted, 1);
    }

    #[test]
    fn clearing_does_not_resurrect_in_flight_sessions() {
        let store = CaptureStore::default();
        let old = begin(&store);
        store.clear();
        store.append(old, Side::Response, b"late");
        store.complete_body(old, Side::Response);
        assert!(store.snapshot().sessions.is_empty());
        assert!(begin(&store).unwrap() > old.unwrap());
    }

    #[test]
    fn pause_only_prevents_new_recordings() {
        let store = CaptureStore::default();
        let id = begin(&store);
        store.set_recording(false);
        assert!(begin(&store).is_none());
        store.append(id, Side::Response, b"already in flight");
        assert_eq!(store.get(id.unwrap()).unwrap().response.total_bytes, 17);
    }

    #[test]
    fn duplicate_headers_are_retained() {
        let mut map = HeaderMap::new();
        map.append("set-cookie", "a=1".parse().unwrap());
        map.append("set-cookie", "b=2".parse().unwrap());
        assert_eq!(headers_from(&map).len(), 2);
    }

    #[test]
    fn invalid_limits_are_rejected() {
        assert!(
            CaptureStore::with_limits(CaptureLimits {
                sessions: 0,
                ..CaptureLimits::default()
            })
            .is_err()
        );
    }

    #[test]
    fn export_snapshots_survive_eviction_while_a_save_dialog_is_open() {
        let store = CaptureStore::default();
        let id = begin(&store);
        store.append(id, Side::Response, b"evidence");
        let snapshot = store.sessions(&[id.unwrap()]);
        let elapsed = snapshot[0].elapsed_ms();
        std::thread::sleep(std::time::Duration::from_millis(10));
        store.clear();
        assert_eq!(snapshot[0].response.data, b"evidence");
        assert_eq!(snapshot[0].elapsed_ms(), elapsed);
        assert!(snapshot[0].duration_ms.is_none());
        assert!(store.all_sessions().is_empty());
    }
}
