//! Deterministic view-only helpers; never infer causes or alter captured evidence.
use crate::{
    capture::{Session, SessionKind, SessionSummary},
    filter::Filter,
};

pub const HIDE_ASSETS_DEFAULT: bool = true;

pub fn matches_view(row: &SessionSummary, filter: &Filter, scope: usize) -> bool {
    filter.matches(row)
        && match scope {
            1 => !row.is_https(),
            2 => row.is_https(),
            3 => row.is_error(),
            4 => row.content_type.contains("json"),
            5 => row.kind != SessionKind::Tunnel,
            _ => true,
        }
}

pub struct ExportSnapshot {
    pub sessions: Vec<Session>,
    pub asset_hidden: usize,
    pub other_excluded: usize,
}

impl ExportSnapshot {
    pub fn counts_message(&self) -> String {
        format!(
            "Export {} visible sessions from this snapshot.\nExcluded: {} hidden by Hide assets; {} excluded by other filters/scope.\nHidden/excluded sessions will NOT be exported.",
            self.sessions.len(),
            self.asset_hidden,
            self.other_excluded
        )
    }
}

pub fn export_snapshot(
    sessions: Vec<Session>,
    filter: &Filter,
    scope: usize,
    hide_assets: bool,
) -> ExportSnapshot {
    let mut snapshot = ExportSnapshot {
        sessions: Vec::new(),
        asset_hidden: 0,
        other_excluded: 0,
    };
    for session in sessions {
        let row = session.summary();
        if !matches_view(&row, filter, scope) {
            snapshot.other_excluded += 1;
        } else if hide_assets && static_asset(&row) {
            snapshot.asset_hidden += 1;
        } else {
            snapshot.sessions.push(session);
        }
    }
    snapshot
}

pub fn problem_marker(row: &SessionSummary) -> bool {
    Review::of(row).is_some()
}

pub fn reason(row: &SessionSummary) -> String {
    let mut text = row.status.map_or_else(
        || "Status not recorded".to_owned(),
        |status| {
            let phrase = http::StatusCode::from_u16(status)
                .ok()
                .and_then(|code| code.canonical_reason())
                .unwrap_or("Status");
            format!("{status} {phrase}")
        },
    );
    if row.failed {
        text.push_str("; recorded transport/source error");
    }
    if matches!(row.status, Some(401 | 407)) {
        text.push_str("; authentication challenge may be expected");
    }
    text
}

pub fn static_asset(row: &SessionSummary) -> bool {
    if row.content_type_ambiguous
        || row.kind != SessionKind::Http
        || row.failed
        || !row.complete
        || !matches!(row.method.as_str(), "GET" | "HEAD")
        || !row
            .status
            .is_some_and(|s| (200..300).contains(&s) || s == 304)
    {
        return false;
    }
    let mime = row
        .content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        mime.as_str(),
        "text/css"
            | "text/javascript"
            | "application/javascript"
            | "application/x-javascript"
            | "image/png"
            | "image/jpeg"
            | "image/gif"
            | "image/webp"
            | "image/avif"
            | "image/svg+xml"
            | "image/bmp"
            | "image/x-icon"
            | "image/vnd.microsoft.icon"
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Review {
    Transport,
    Server,
    Throttling,
    Forbidden,
    Authentication,
    Client,
}
impl Review {
    pub fn of(row: &SessionSummary) -> Option<Self> {
        if row.failed {
            return Some(Self::Transport);
        }
        match row.status? {
            500..=599 => Some(Self::Server),
            429 => Some(Self::Throttling),
            403 => Some(Self::Forbidden),
            401 | 407 => Some(Self::Authentication),
            400..=499 => Some(Self::Client),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Transport => "Recorded transport/source error",
            Self::Server => "5xx: review server response",
            Self::Throttling => "429: review throttling",
            Self::Forbidden => "403: review access",
            Self::Authentication => "Auth challenge: may be expected",
            Self::Client => "4xx: review request/response",
        }
    }
    pub fn urgent(self) -> bool {
        matches!(self, Self::Transport | Self::Server)
    }
}

pub fn review_order(rows: &[SessionSummary]) -> Vec<u64> {
    let mut candidates: Vec<_> = rows
        .iter()
        .filter_map(|r| Review::of(r).map(|p| (p, r.id)))
        .collect();
    candidates.sort_unstable();
    candidates.into_iter().map(|(_, id)| id).collect()
}

#[derive(Debug)]
pub struct Matches {
    pub ranges: Vec<(usize, usize)>,
    pub limited: bool,
}

pub fn find_matches(text: &str, query: &str, match_case: bool) -> Matches {
    const MAX_MATCHES: usize = 10_000;
    let mut result = Matches {
        ranges: Vec::new(),
        limited: false,
    };
    if query.is_empty() {
        return result;
    }
    // Map folded UTF-8 byte positions back to source UTF-16 edit-control offsets.
    let mut folded = String::with_capacity(text.len());
    let mut mapping = Vec::with_capacity(text.len());
    let mut append = |ch: char, start, end| {
        folded.push(ch);
        mapping.extend(std::iter::repeat_n((start, end), ch.len_utf8()));
    };
    let mut offset = 0;
    for ch in text.chars() {
        let end = offset + ch.len_utf16();
        if match_case {
            append(ch, offset, end);
        } else {
            for lower in ch.to_lowercase() {
                append(lower, offset, end);
            }
        }
        offset = end;
    }
    let query = if match_case {
        query.to_owned()
    } else {
        query.chars().flat_map(char::to_lowercase).collect()
    };
    for (start, matched) in folded.match_indices(&query) {
        let range = (mapping[start].0, mapping[start + matched.len() - 1].1);
        if result.ranges.last() == Some(&range) {
            continue;
        }
        if result.ranges.len() == MAX_MATCHES {
            result.limited = true;
            break;
        }
        result.ranges.push(range);
    }
    result
}

pub fn next_match(
    ranges: &[(usize, usize)],
    previous: Option<(usize, usize)>,
    backwards: bool,
) -> Option<(usize, bool)> {
    if ranges.is_empty() {
        return None;
    }
    let Some(previous) = previous else {
        return Some((if backwards { ranges.len() - 1 } else { 0 }, false));
    };
    if backwards {
        ranges
            .iter()
            .rposition(|r| r.0 < previous.0)
            .map(|i| (i, false))
            .or(Some((ranges.len() - 1, true)))
    } else {
        ranges
            .iter()
            .position(|r| r.0 >= previous.1)
            .map(|i| (i, false))
            .or(Some((0, true)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::CaptureStore;
    fn row(status: u16, mime: &str) -> SessionSummary {
        let store = CaptureStore::default();
        let id = store.begin(
            &http::Method::GET,
            &"https://example.test/api.js".parse().unwrap(),
            http::Version::HTTP_11,
            &http::HeaderMap::new(),
            "127.0.0.1:1".parse().unwrap(),
        );
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", mime.parse().unwrap());
        store.response(id, status, http::Version::HTTP_11, &headers);
        let mut row = store.get(id.unwrap()).unwrap().summary();
        row.complete = true;
        row
    }
    #[test]
    fn default_hiding_and_compact_markers_cover_all_http_errors() {
        const { assert!(HIDE_ASSETS_DEFAULT) };
        for status in 100..=599 {
            let r = row(status, "text/css");
            assert_eq!(problem_marker(&r), status >= 400);
            if status >= 400 {
                assert!(!static_asset(&r));
            }
        }
        assert_eq!(reason(&row(400, "")), "400 Bad Request");
        assert_eq!(reason(&row(503, "")), "503 Service Unavailable");
        assert!(reason(&row(401, "")).contains("may be expected"));
        let mut r = row(200, "text/css");
        r.failed = true;
        assert!(problem_marker(&r));
        assert!(reason(&r).contains("recorded transport/source error"));
        r.status = None;
        assert!(problem_marker(&r));
    }
    #[test]
    fn assets_require_clear_successful_safe_method_and_mime() {
        for mime in [
            "text/css",
            "application/javascript",
            "image/png",
            "IMAGE/SVG+XML; charset=utf-8",
        ] {
            assert!(static_asset(&row(200, mime)));
            assert!(static_asset(&row(304, mime)));
            for status in [302, 401, 403, 404, 429, 500] {
                assert!(!static_asset(&row(status, mime)));
            }
        }
        for mime in [
            "application/json",
            "text/html",
            "",
            "image/unknown",
            "application/octet-stream",
        ] {
            assert!(!static_asset(&row(200, mime)));
        }
        let mut r = row(200, "text/css");
        r.method = "POST".into();
        assert!(!static_asset(&r));
        r.method = "HEAD".into();
        assert!(static_asset(&r));
        r.failed = true;
        assert!(!static_asset(&r));
        r.failed = false;
        r.complete = false;
        assert!(!static_asset(&r));
    }
    #[test]
    fn review_is_deterministic_visible_scope_and_not_body_availability() {
        let statuses = [401, 404, 403, 429, 503, 200];
        let mut rows: Vec<_> = statuses
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let mut r = row(*s, "application/json");
                r.id = i as u64 + 1;
                r
            })
            .collect();
        assert_eq!(review_order(&rows), vec![5, 4, 3, 1, 2]);
        assert_eq!(
            rows.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5, 6]
        );
        rows[5].failed = true;
        assert_eq!(review_order(&rows)[0], 6);
        assert_eq!(Review::of(&row(407, "")).unwrap(), Review::Authentication);
        assert_eq!(Review::of(&row(200, "")), None);
    }
    #[test]
    fn unicode_offsets_case_and_wrap_match_native_utf16() {
        let matches = find_matches("😀 Écho éCHO İx", "écho", false);
        assert_eq!(matches.ranges, vec![(3, 7), (8, 12)]);
        assert_eq!(
            find_matches("😀 Écho éCHO", "Écho", true).ranges,
            vec![(3, 7)]
        );
        assert_eq!(find_matches("İx", "i", false).ranges, vec![(0, 1)]);
        assert_eq!(next_match(&matches.ranges, None, false), Some((0, false)));
        assert_eq!(
            next_match(&matches.ranges, Some((8, 12)), false),
            Some((0, true))
        );
        assert_eq!(
            next_match(&matches.ranges, Some((3, 7)), true),
            Some((1, true))
        );
        assert!(find_matches("secret", "absent", false).ranges.is_empty());
        assert!(find_matches("text", "", false).ranges.is_empty());
        assert!(find_matches(&"x".repeat(10001), "x", false).limited);
    }
}
