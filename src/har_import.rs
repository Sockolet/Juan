//! Offline HAR evidence. Browser bodies are not reconstructed HTTP wire messages.
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufReader, Read},
    path::Path,
    sync::Arc,
    time::Instant,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde::de::{DeserializeSeed, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    capture::{ArchiveInfo, CaptureLimits, CapturedBody, Header, Session, SessionKind, Side},
    har::{ExportMode, export_headers, sanitize_url},
    saz::ImportedArchive,
};

pub const INPUT_LIMIT: u64 = 134_217_728;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum Representation {
    Text,
    DecodedBinary,
    Wire,
    Unavailable,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct BodyEvidence {
    pub representation: Representation,
    pub availability: String,
    pub wire_size: i64,
    pub decoded_size: i64,
    pub mime: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Summary {
    pub source: &'static str,
    pub time: f64,
    pub request: BodyEvidence,
    pub response: BodyEvidence,
    pub request_retained_bytes: usize,
    pub response_retained_bytes: usize,
    pub request_available_bytes: u64,
    pub response_available_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct Evidence {
    pub creator: Arc<Agent>,
    pub browser: Option<Arc<Agent>>,
    pub request: BodyEvidence,
    pub response: BodyEvidence,
    pub params: Vec<Parameter>,
    pub timings: BTreeMap<String, f64>,
    pub time: f64,
    pub status_text: String,
    pub redirect: String,
    pub server_ip: String,
    pub connection: String,
    pub request_headers_size: i64,
    pub response_headers_size: i64,
}

impl Evidence {
    pub fn body(&self, side: Side) -> &BodyEvidence {
        match side {
            Side::Request => &self.request,
            Side::Response => &self.response,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, serde::Serialize)]
pub struct Agent {
    pub name: String,
    #[serde(default)]
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Parameter {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    started_date_time: String,
    #[serde(default = "unknown")]
    time: f64,
    request: Request,
    response: Response,
    #[serde(default, deserialize_with = "timings")]
    timings: BTreeMap<String, f64>,
    #[serde(default)]
    server_ip_address: String,
    #[serde(default)]
    connection: String,
    #[serde(default, rename = "_error")]
    error: Option<String>,
    #[serde(default, rename = "_juan")]
    juan: Juan,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Juan {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    source_creator: Option<Agent>,
    #[serde(default)]
    source_browser: Option<Agent>,
}

fn timings<'de, D: serde::Deserializer<'de>>(d: D) -> Result<BTreeMap<String, f64>, D::Error> {
    struct Timings;
    impl<'de> Visitor<'de> for Timings {
        type Value = BTreeMap<String, f64>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("HAR timings")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut timings = BTreeMap::new();
            while let Some(key) = map.next_key::<String>()? {
                if [
                    "blocked", "dns", "connect", "ssl", "send", "wait", "receive",
                ]
                .contains(&key.as_str())
                {
                    if timings.insert(key, map.next_value()?).is_some() {
                        return Err(M::Error::custom("Duplicate HAR timing"));
                    }
                } else {
                    map.next_value::<IgnoredAny>()?;
                }
            }
            Ok(timings)
        }
    }
    d.deserialize_map(Timings)
}
fn unknown() -> f64 {
    -1.0
}
fn unknown_size() -> i64 {
    -1
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    method: String,
    url: String,
    #[serde(default)]
    http_version: String,
    headers: Vec<Header>,
    #[serde(default = "unknown_size")]
    body_size: i64,
    #[serde(default = "unknown_size")]
    headers_size: i64,
    #[serde(default)]
    post_data: Option<Value>,
    #[serde(default, rename = "_bodyOmitted")]
    omitted: bool,
    #[serde(default, rename = "_capture")]
    capture: Option<Value>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Response {
    #[serde(default)]
    status: u16,
    #[serde(default)]
    status_text: String,
    #[serde(default)]
    http_version: String,
    headers: Vec<Header>,
    #[serde(default = "unknown_size")]
    body_size: i64,
    #[serde(default = "unknown_size")]
    headers_size: i64,
    content: Value,
    #[serde(default)]
    redirect_url: String,
}

pub fn load(path: &Path, limits: CaptureLimits) -> Result<ImportedArchive> {
    let file = File::open(path).with_context(|| format!("Open HAR {}", path.display()))?;
    ensure!(
        file.metadata()?.len() <= INPUT_LIMIT,
        "HAR exceeds 128 MiB input limit"
    );
    read(file, limits)
}

// Fail upon the first byte beyond the cap, even if the file grew after stat().
struct Bounded<R> {
    source: R,
    remaining: u64,
}
impl<R: Read> Read for Bounded<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut extra = [0];
            return match self.source.read(&mut extra)? {
                0 => Ok(0),
                _ => Err(std::io::Error::other("HAR exceeds 128 MiB input limit")),
            };
        }
        let size = buf.len().min(self.remaining as usize);
        let count = self.source.read(&mut buf[..size])?;
        self.remaining -= count as u64;
        Ok(count)
    }
}

pub fn read(source: impl Read, limits: CaptureLimits) -> Result<ImportedArchive> {
    ensure!(
        limits.sessions > 0
            && limits.body_bytes > 0
            && limits.total_body_bytes >= limits.body_bytes,
        "Invalid HAR retention limits"
    );
    let mut source = Bounded {
        source,
        remaining: INPUT_LIMIT,
    };
    let mut prefix = Vec::with_capacity(3);
    source
        .by_ref()
        .take(3)
        .read_to_end(&mut prefix)
        .context("Read HAR prefix")?;
    // Only a leading UTF-8 BOM is optional. Its bytes still consume the input budget.
    if prefix == b"\xef\xbb\xbf" {
        prefix.clear();
    }
    // Convert one entry at a time rather than retaining the entire JSON capture.
    let mut parser = serde_json::Deserializer::from_reader(BufReader::new(
        std::io::Cursor::new(prefix).chain(source),
    ));
    let imported = RootSeed(limits)
        .deserialize(&mut parser)
        .context("Parse HAR 1.2")?;
    parser
        .end()
        .context("Trailing HAR data or input limit exceeded")?;
    Ok(imported)
}

struct RootSeed(CaptureLimits);
impl<'de> DeserializeSeed<'de> for RootSeed {
    type Value = ImportedArchive;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for RootSeed {
    type Value = ImportedArchive;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("HAR document")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut log = None;
        while let Some(key) = map.next_key::<String>()? {
            if key == "log" {
                if log.is_some() {
                    return Err(M::Error::custom("Duplicate HAR log"));
                }
                log = Some(map.next_value_seed(LogSeed(self.0))?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        log.ok_or_else(|| M::Error::missing_field("log"))
    }
}
struct LogSeed(CaptureLimits);
impl<'de> DeserializeSeed<'de> for LogSeed {
    type Value = ImportedArchive;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for LogSeed {
    type Value = ImportedArchive;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("HAR log")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut version: Option<String> = None;
        let mut creator: Option<Agent> = None;
        let mut browser: Option<Agent> = None;
        let mut imported = None;
        let mut seen = std::collections::BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if ["version", "creator", "browser", "entries"].contains(&key.as_str())
                && !seen.insert(key.clone())
            {
                return Err(M::Error::custom(format!("Duplicate log field {key}")));
            }
            match key.as_str() {
                "version" => version = Some(map.next_value()?),
                "creator" => creator = Some(map.next_value()?),
                "browser" => browser = map.next_value()?,
                "entries" => imported = Some(map.next_value_seed(EntriesSeed(self.0))?),
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        if version.as_deref() != Some("1.2") {
            return Err(M::Error::custom("Only HAR 1.2 is supported"));
        }
        let creator = Arc::new(creator.ok_or_else(|| M::Error::missing_field("creator"))?);
        let browser = browser.map(Arc::new);
        let mut imported = imported.ok_or_else(|| M::Error::missing_field("entries"))?;
        for session in &mut imported.sessions {
            if let Some(evidence) = session.archive.as_mut().and_then(|a| a.har.as_mut()) {
                if evidence.creator.name.is_empty() {
                    evidence.creator = creator.clone();
                }
                if evidence.browser.is_none() {
                    evidence.browser = browser.clone();
                }
            }
        }
        Ok(imported)
    }
}
struct EntriesSeed(CaptureLimits);
impl<'de> DeserializeSeed<'de> for EntriesSeed {
    type Value = ImportedArchive;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_seq(self)
    }
}
impl<'de> Visitor<'de> for EntriesSeed {
    type Value = ImportedArchive;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("HAR entry array")
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        let mut imported = ImportedArchive {
            sessions: Vec::new(),
            warnings: Vec::new(),
        };
        let mut remaining = self.0.total_body_bytes;
        while let Some(entry) = seq.next_element::<Entry>()? {
            if imported.sessions.len() >= self.0.sessions {
                return Err(S::Error::custom("HAR exceeds session retention limit"));
            }
            let id = imported.sessions.len() as u64 + 1;
            let session = convert(entry, id, self.0, &mut remaining, &mut imported.warnings)
                .map_err(|e| S::Error::custom(format!("HAR entry {id}: {e:#}")))?;
            imported.sessions.push(session);
        }
        if imported.sessions.is_empty() {
            return Err(S::Error::custom("HAR contains no sessions"));
        }
        Ok(imported)
    }
}

fn body(
    value: Option<&Value>,
    wire_size: i64,
    limits: CaptureLimits,
    remaining: &mut usize,
    warnings: &mut Vec<String>,
    label: &str,
    source_flags: (bool, Option<&Value>),
) -> (CapturedBody, BodyEvidence) {
    let (omitted, capture) = source_flags;
    let mut evidence = BodyEvidence {
        representation: Representation::Unavailable,
        availability: "absent from export".into(),
        wire_size,
        decoded_size: value
            .and_then(|v| v["size"].as_i64())
            .filter(|v| *v >= -1)
            .unwrap_or(-1),
        mime: value
            .and_then(|v| v["mimeType"].as_str())
            .unwrap_or("")
            .into(),
    };
    let mut output = CapturedBody::default();
    let Some(value) = value else {
        if omitted {
            evidence.availability = "omitted by source".into();
        }
        return (output, evidence);
    };
    if !value.is_object() {
        evidence.availability = "invalid optional body".into();
        warnings.push(format!("{label}: invalid optional body"));
        return (output, evidence);
    }
    if omitted || value["_bodyOmitted"] == true {
        evidence.availability = "omitted by source".into();
        return (output, evidence);
    }
    let keep_limit = limits.body_bytes.min(*remaining);
    let decoded = if let Some(text) = value.get("_wireBodyBase64") {
        evidence.representation = Representation::Wire;
        text.as_str()
            .and_then(|s| decode_prefix(s, keep_limit).ok())
    } else if let Some(text) = value.get("text") {
        match value.get("encoding").map(Value::as_str) {
            None | Some(Some("")) => {
                evidence.representation = Representation::Text;
                text.as_str().map(|s| {
                    (
                        s.as_bytes()[..s.len().min(keep_limit)].to_vec(),
                        s.len() as u64,
                    )
                })
            }
            Some(Some("base64")) => {
                evidence.representation = Representation::DecodedBinary;
                text.as_str()
                    .and_then(|s| decode_prefix(s, keep_limit).ok())
            }
            _ => None,
        }
    } else {
        if value.get("params").is_some() {
            evidence.availability = "structured parameters only; no original body bytes".into();
        }
        if let Some(availability) = value["_harBody"]["availability"].as_str()
            && [
                "absent from export",
                "omitted by source",
                "invalid or unsupported body encoding",
                "invalid optional body",
                "structured parameters only; no original body bytes",
            ]
            .contains(&availability)
        {
            evidence.availability = availability.into();
        }
        return (output, evidence);
    };
    let Some((bytes, available)) = decoded else {
        evidence.representation = Representation::Unavailable;
        evidence.availability = "invalid or unsupported body encoding".into();
        warnings.push(format!("{label}: {}", evidence.availability));
        return (output, evidence);
    };
    if evidence.representation == Representation::DecodedBinary
        && value["_harBody"]["representation"] == "Text"
    {
        evidence.representation = Representation::Text;
    }
    output.total_bytes = value["_harBody"]["availableBytes"]
        .as_u64()
        .filter(|n| *n >= available)
        .unwrap_or(available);
    let metadata = capture.unwrap_or(&value["_capture"]);
    let partial =
        value["_partial"] == true || metadata["complete"] == false || metadata["truncated"] == true;
    let truncated = output.total_bytes > bytes.len() as u64;
    *remaining -= bytes.len();
    output.data = bytes;
    output.complete = !partial;
    evidence.availability = if truncated {
        "locally retention-truncated"
    } else if partial {
        "partial in source"
    } else {
        "present"
    }
    .into();
    if truncated {
        warnings.push(format!("{label}: body retention limit reached"));
    }
    (output, evidence)
}

fn decode_prefix(text: &str, keep: usize) -> std::io::Result<(Vec<u8>, u64)> {
    let mut reader = base64::read::DecoderReader::new(text.as_bytes(), &STANDARD);
    let mut bytes = Vec::new();
    let mut count = 0;
    let mut chunk = [0; 8192];
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        let retain = n.min(keep - bytes.len());
        bytes.extend_from_slice(&chunk[..retain]);
    }
    Ok((bytes, count))
}

fn convert(
    mut entry: Entry,
    id: u64,
    limits: CaptureLimits,
    remaining: &mut usize,
    warnings: &mut Vec<String>,
) -> Result<Session> {
    ensure!(
        (entry.time == -1.0 || entry.time >= 0.0) && entry.time.is_finite(),
        "Invalid total timing"
    );
    ensure!(
        entry
            .timings
            .values()
            .all(|t| t.is_finite() && (*t == -1.0 || *t >= 0.0)),
        "Invalid HAR timing"
    );
    ensure!(
        entry.request.body_size >= -1 && entry.response.body_size >= -1,
        "Invalid body size"
    );
    ensure!(
        entry.request.headers_size >= -1 && entry.response.headers_size >= -1,
        "Invalid headers size"
    );
    for phase in ["send", "wait", "receive"] {
        entry.timings.entry(phase.into()).or_insert(-1.0);
    }
    ensure!(
        entry.response.content.is_object(),
        "Response content must be an object"
    );
    http::Method::from_bytes(entry.request.method.as_bytes()).context("Invalid request method")?;
    let started_at = OffsetDateTime::parse(&entry.started_date_time, &Rfc3339)
        .context("Invalid startedDateTime")?;
    let uri: http::Uri = entry.request.url.parse().context("Invalid request URL")?;
    ensure!(
        uri.scheme().is_some() && uri.authority().is_some(),
        "Expected absolute request URL"
    );
    ensure!(
        entry.response.status == 0 || (100..=599).contains(&entry.response.status),
        "Invalid response status"
    );
    let host = uri.host().unwrap_or("").to_owned();
    let path = uri
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or("/")
        .to_owned();
    let (request, request_evidence) = body(
        entry.request.post_data.as_ref(),
        entry.request.body_size,
        limits,
        remaining,
        warnings,
        &format!("Entry {id} request"),
        (entry.request.omitted, entry.request.capture.as_ref()),
    );
    let (response, response_evidence) = body(
        Some(&entry.response.content),
        entry.response.body_size,
        limits,
        remaining,
        warnings,
        &format!("Entry {id} response"),
        (false, None),
    );
    let params = match entry
        .request
        .post_data
        .as_mut()
        .and_then(|p| p.get_mut("params"))
    {
        Some(value) => match serde_json::from_value::<Vec<Parameter>>(value.take()) {
            Ok(params) => params,
            Err(_) => {
                warnings.push(format!("Entry {id}: invalid optional postData.params"));
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    let complete = request.complete && response.complete;
    let evidence = Evidence {
        creator: Arc::new(entry.juan.source_creator.unwrap_or_default()),
        browser: entry.juan.source_browser.map(Arc::new),
        request: request_evidence,
        response: response_evidence,
        params,
        timings: entry.timings,
        time: entry.time,
        status_text: entry.response.status_text,
        redirect: entry.response.redirect_url,
        server_ip: entry.server_ip_address,
        connection: entry.connection,
        request_headers_size: entry.request.headers_size,
        response_headers_size: entry.response.headers_size,
    };
    Ok(Session {
        id, method: entry.request.method, url: entry.request.url, host, path,
        protocol: entry.request.http_version, response_protocol: entry.response.http_version,
        client: String::new(), kind: SessionKind::Http, started_at: Some(started_at),
        started: Instant::now(), duration_ms: (entry.time >= 0.0).then_some(entry.time as u64),
        headers_ms: None, status: (entry.response.status != 0).then_some(entry.response.status),
        request_headers: entry.request.headers, response_headers: entry.response.headers,
        request, response,         error: entry.error.or(entry.juan.error),
        archive: Some(ArchiveInfo {
            har: Some(evidence), original_id: id, bit_flags: None,
            flags: BTreeMap::new(), timers: BTreeMap::new(), notes: vec![
                "HAR browser-exported evidence, not wire capture. Sizes may be unknown. No replay or WebSocket frames. Unrecognized extensions, pages, cache, structured cookies and query arrays are not retained.".into()
            ], complete,
        }),
        snapshot_elapsed_ms: None,
    })
}

fn exported_body(session: &Session, evidence: &Evidence, side: Side, mode: ExportMode) -> Value {
    let metadata = evidence.body(side);
    let body = session.body(side);
    let mut value = json!({
        "mimeType": metadata.mime, "size": metadata.decoded_size,
        "_capture": {
            "complete": body.complete, "truncated": body.truncated(),
            "capturedBytes": body.data.len(),
        },
        "_harBody": { "representation": format!("{:?}", metadata.representation),
            "availability": metadata.availability, "availableBytes": body.total_bytes },
    });
    if mode == ExportMode::Sanitized {
        value["_bodyOmitted"] = json!(true);
    } else if metadata.representation != Representation::Unavailable {
        if metadata.representation == Representation::Wire {
            value["_wireBodyBase64"] = json!(STANDARD.encode(&body.data));
        } else if metadata.representation == Representation::DecodedBinary {
            value["text"] = json!(STANDARD.encode(&body.data));
            value["encoding"] = json!("base64");
        } else if let Ok(text) = std::str::from_utf8(&body.data) {
            value["text"] = json!(text);
        } else {
            value["text"] = json!(STANDARD.encode(&body.data));
            value["encoding"] = json!("base64");
        }
        if !body.complete || body.truncated() {
            value["_partial"] = json!(true);
        }
    } else if metadata.availability == "omitted by source" {
        value["_bodyOmitted"] = json!(true);
    }
    value
}

pub(crate) fn export_entry(
    session: &Session,
    evidence: &Evidence,
    mode: ExportMode,
) -> Result<Value> {
    let full = mode == ExportMode::Full;
    let mut request = json!({
        "method": session.method,
        "url": if full { session.url.clone() } else { sanitize_url(&session.url) },
        "httpVersion": session.protocol,
        "headers": export_headers(&session.request_headers, mode),
        "cookies": [], "queryString": [], "headersSize": evidence.request_headers_size,
        "bodySize": evidence.request.wire_size,
    });
    let mut post = exported_body(session, evidence, Side::Request, mode);
    if full && !evidence.params.is_empty() {
        post["params"] = json!(evidence.params);
    }
    request["postData"] = post;
    if !full {
        request["_bodyOmitted"] = json!(true);
    }
    Ok(json!({
        "startedDateTime": session.started_at.context("HAR start time missing")?.format(&Rfc3339)?,
        "time": evidence.time, "timings": evidence.timings,
        "request": request,
        "response": {
            "status": session.status.unwrap_or(0), "statusText": if full { evidence.status_text.as_str() } else { "" },
            "httpVersion": session.response_protocol,
            "headers": export_headers(&session.response_headers, mode), "cookies": [],
            "content": exported_body(session, evidence, Side::Response, mode),
            "redirectURL": if full { evidence.redirect.clone() } else { sanitize_url(&evidence.redirect) },
            "headersSize": evidence.response_headers_size, "bodySize": evidence.response.wire_size,
        },
        "serverIPAddress": if full { evidence.server_ip.as_str() } else { "" },
        "connection": if full { evidence.connection.as_str() } else { "" },
        "cache": {},
        "_error": if full { session.error.as_deref() } else { session.error.as_ref().map(|_| "Source error; details omitted") },
        "_juan": { "source": "HAR", "sourceEntry": session.archive.as_ref().map(|a| a.original_id),
            "sanitized": !full,
            "sourceCreator": if full { Some(evidence.creator.as_ref()) } else { None },
            "sourceBrowser": if full { evidence.browser.as_deref() } else { None },
            "timingNote": "Recorded HAR timings; not importer measurements" },
        "comment": "Browser-exported evidence; not wire capture. Sanitized output is not anonymized; review URLs and custom headers before sharing.",
    }))
}

pub fn describe(session: &Session, evidence: &Evidence, side: Side) -> String {
    let b = evidence.body(side);
    let body = session.body(side);
    format!(
        "HAR SOURCE: {:?}; {}. Retained {} bytes; available representation {} bytes; reported wire {} bytes; reported decoded {} bytes (-1 = unknown).\r\n",
        b.representation,
        b.availability,
        body.data.len(),
        body.total_bytes,
        b.wire_size,
        b.decoded_size
    )
}
