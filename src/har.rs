use std::{
    io::{BufWriter, Write},
    path::Path,
};

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;

use crate::{
    capture::{CapturedBody, Header, Session, SessionKind, Side, header},
    inspect::{DECODE_LIMIT, decode_body},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportMode {
    Sanitized,
    Full,
}

pub fn export(path: &Path, sessions: &[Session], mode: ExportMode) -> Result<()> {
    crate::archive::atomic_write(path, |file| {
        let mut writer = BufWriter::new(file);
        write_har(&mut writer, sessions, mode)?;
        writer.flush().context("Flush HAR output")?;
        Ok(())
    })
}

pub fn write_har(mut writer: impl Write, sessions: &[Session], mode: ExportMode) -> Result<()> {
    writer.write_all(
        concat!(
            "{\"log\":{\"version\":\"1.2\",\"creator\":{\"name\":\"Juan\",\"version\":\"",
            env!("CARGO_PKG_VERSION"),
            "\"},\"entries\":["
        )
        .as_bytes(),
    )?;
    for (index, session) in sessions.iter().enumerate() {
        if index > 0 {
            writer.write_all(b",")?;
        }
        serde_json::to_writer(&mut writer, &entry(session, mode)?)?;
    }
    writer.write_all(b"]}}")?;
    Ok(())
}

fn sensitive(name: &str) -> bool {
    let normalized: String = name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect();
    matches!(
        normalized.as_str(),
        "authorization"
            | "proxyauthorization"
            | "cookie"
            | "setcookie"
            | "key"
            | "code"
            | "sig"
            | "signature"
            | "session"
            | "sessionid"
            | "jwt"
            | "assertion"
            | "ticket"
            | "credential"
            | "credentials"
    ) || normalized.ends_with("key")
        || normalized.ends_with("sessionid")
        || [
            "token",
            "secret",
            "password",
            "authorization",
            "credential",
            "signature",
            "cookie",
        ]
        .iter()
        .any(|part| normalized.contains(part))
}

pub fn sanitize_url(url: &str) -> String {
    let without_fragment = url.split('#').next().unwrap_or(url);
    let (prefix, query) = without_fragment
        .split_once('?')
        .map_or((without_fragment, None), |(p, q)| (p, Some(q)));
    let mut prefix = prefix.to_owned();
    if let Some(scheme) = prefix.find("://") {
        let start = scheme + 3;
        let end = prefix[start..]
            .find('/')
            .map_or(prefix.len(), |end| start + end);
        if let Some(at) = prefix[start..end].rfind('@') {
            prefix.replace_range(start..=start + at, "");
        }
    }
    let Some(query) = query else { return prefix };
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        serializer.append_pair(
            &name,
            if sensitive(&name) {
                "[REDACTED]"
            } else {
                &value
            },
        );
    }
    format!("{prefix}?{}", serializer.finish())
}

pub(crate) fn export_headers(headers: &[Header], mode: ExportMode) -> Vec<Header> {
    headers
        .iter()
        .map(|h| Header {
            name: h.name.clone(),
            value: if mode == ExportMode::Full {
                h.value.clone()
            } else if sensitive(&h.name) {
                "[REDACTED]".into()
            } else if ["location", "referer", "content-location"]
                .iter()
                .any(|name| h.name.eq_ignore_ascii_case(name))
            {
                sanitize_url(&h.value)
            } else {
                h.value.clone()
            },
        })
        .collect()
}

fn body_metadata(body: &CapturedBody) -> Value {
    json!({
        "capturedBytes": body.data.len(),
        "transferredBytes": body.total_bytes,
        "truncated": body.truncated(),
        "complete": body.complete,
    })
}

fn entry(session: &Session, mode: ExportMode) -> Result<Value> {
    let opaque = session.kind != SessionKind::Http;
    let url = if session.kind == SessionKind::Tunnel {
        format!("https://{}/", session.url)
    } else {
        session.url.clone()
    };
    let valid_target = url
        .parse::<http::Uri>()
        .is_ok_and(|uri| uri.scheme().is_some() && uri.authority().is_some());
    let original_target = if mode == ExportMode::Sanitized {
        sanitize_url(&session.url)
    } else {
        session.url.clone()
    };
    let url = if !valid_target {
        "http://invalid-request.invalid/".to_owned()
    } else if mode == ExportMode::Sanitized {
        sanitize_url(&url)
    } else {
        url
    };
    let query = url
        .split_once('?')
        .map_or("", |(_, query)| query.split('#').next().unwrap_or(query));
    let query: Vec<Value> = form_urlencoded::parse(query.as_bytes())
        .map(|(name, value)| json!({ "name": name, "value": value }))
        .collect();
    let request_type =
        header(&session.request_headers, "content-type").unwrap_or("application/octet-stream");
    let response_type =
        header(&session.response_headers, "content-type").unwrap_or("application/octet-stream");
    let encoded = has_encoding(session, Side::Response);
    let mut content = json!({
        "size": if opaque { json!(0) } else if encoded { json!(-1) } else { json!(session.response.total_bytes) },
        "mimeType": response_type,
        "_capture": body_metadata(&session.response),
    });
    let mut request = json!({
        "method": session.method,
        "url": url,
        "httpVersion": session.protocol,
        "cookies": [],
        "headers": export_headers(&session.request_headers, mode),
        "queryString": query,
        "headersSize": -1,
        "bodySize": if opaque { 0 } else { session.request.total_bytes },
        "_capture": body_metadata(&session.request),
        "_trailers": export_headers(&session.request.trailers, mode),
    });
    if mode == ExportMode::Full && !opaque {
        fill_content(&mut content, session, Side::Response);
        if session.request.total_bytes > 0 {
            let mut post = json!({ "mimeType": request_type });
            fill_content(&mut post, session, Side::Request);
            request["postData"] = post;
        }
    } else {
        content["_bodyOmitted"] = json!(true);
        request["_bodyOmitted"] = json!(true);
        content["comment"] = json!(if opaque {
            "Opaque tunnel payload is not retained"
        } else {
            "Body omitted by sanitized export. Decoded size is -1 when unknown; bodySize counts transferred bytes."
        });
    }
    let elapsed = session
        .elapsed_ms()
        .context("This session has no recorded duration; export SAZ to preserve unknown timings")?;
    let started_at = session.started_at.context(
        "This session has no recorded start time; export SAZ to preserve unknown timings",
    )?;
    let wait = session.headers_ms.unwrap_or(elapsed).min(elapsed);
    let location = header(&session.response_headers, "location").unwrap_or("");
    Ok(json!({
        "startedDateTime": started_at.format(&Rfc3339)?,
        "time": elapsed,
        "request": request,
        "response": {
            "status": session.status.unwrap_or(0),
            "statusText": session.status.and_then(|s| http::StatusCode::from_u16(s).ok())
                .and_then(|s| s.canonical_reason()).unwrap_or(""),
            "httpVersion": session.response_protocol,
            "cookies": [],
            "headers": export_headers(&session.response_headers, mode),
            "content": content,
            "redirectURL": if mode == ExportMode::Sanitized { sanitize_url(location) } else { location.to_owned() },
            "headersSize": -1,
            "bodySize": if opaque { 0 } else { session.response.total_bytes },
            "_trailers": export_headers(&session.response.trailers, mode),
        },
        "cache": {},
        "timings": { "blocked": -1, "dns": -1, "connect": -1, "ssl": -1, "send": 0, "wait": wait, "receive": elapsed - wait },
        "_juan": {
            "sessionId": session.id,
            "error": if mode == ExportMode::Full { session.error.as_deref() } else { session.error.as_ref().map(|_| "Proxy error; details omitted from sanitized export") },
            "sanitized": mode == ExportMode::Sanitized,
            "opaqueTunnel": opaque,
            "complete": session.capture_complete(),
            "invalidRequestTarget": !valid_target,
            "originalRequestTarget": if valid_target { None } else { Some(original_target) },
            "timingNote": "wait includes request upload; DNS/TCP/TLS not individually measured",
        },
        "comment": if mode == ExportMode::Sanitized {
            "Bodies omitted; common credential headers and query parameters redacted. Not anonymized: review URLs, paths and custom headers before sharing."
        } else {
            "Sensitive full capture. Truncated or undecodable bodies are explicitly marked."
        },
    }))
}

fn has_encoding(session: &Session, side: Side) -> bool {
    header(session.headers(side), "content-encoding")
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .any(|encoding| !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity"))
}

fn fill_content(content: &mut Value, session: &Session, side: Side) {
    let body = session.body(side);
    match decode_body(session, side, DECODE_LIMIT) {
        Ok(data) => {
            content["size"] = if !has_encoding(session, side) {
                json!(body.total_bytes)
            } else if body.complete && !body.truncated() {
                json!(data.len())
            } else {
                json!(-1)
            };
            if let Ok(text) = std::str::from_utf8(&data) {
                content["text"] = json!(text);
            } else {
                content["text"] = json!(STANDARD.encode(&data));
                content["encoding"] = json!("base64");
            }
            if body.truncated() || !body.complete {
                content["_partial"] = json!(true);
                content["comment"] =
                    json!("Only the retained prefix is included; consult _capture");
            }
        }
        Err(error) => {
            content["size"] = json!(-1);
            content["_wireBodyBase64"] = json!(STANDARD.encode(&body.data));
            content["comment"] = json!(format!(
                "Decoded content unavailable: {error:#}. Original captured bytes are in _wireBodyBase64."
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::CaptureStore;

    fn sample() -> Session {
        let store = CaptureStore::default();
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", "Bearer private-value".parse().unwrap());
        let id = store.begin(
            &http::Method::POST,
            &"https://example.test/?token=private-token&ok=1"
                .parse()
                .unwrap(),
            http::Version::HTTP_11,
            &headers,
            "127.0.0.1:1".parse().unwrap(),
        );
        store.response(id, 200, http::Version::HTTP_11, &http::HeaderMap::new());
        store.append(id, Side::Request, b"secret-body");
        store.append(id, Side::Response, &[0, 255, 1]);
        store.complete_body(id, Side::Response);
        store.get(id.unwrap()).unwrap()
    }

    #[test]
    fn sanitized_har_omits_bodies_and_common_credentials() {
        let mut output = Vec::new();
        write_har(&mut output, &[sample()], ExportMode::Sanitized).unwrap();
        let text = String::from_utf8(output).unwrap();
        for secret in ["private-value", "private-token", "secret-body"] {
            assert!(!text.contains(secret), "{secret}");
        }
        let har: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(har["log"]["version"], "1.2");
        assert_eq!(
            har["log"]["entries"][0]["response"]["content"]["_bodyOmitted"],
            true
        );
    }

    #[test]
    fn full_har_preserves_binary_as_base64() {
        let value = entry(&sample(), ExportMode::Full).unwrap();
        assert_eq!(value["response"]["content"]["encoding"], "base64");
        assert_eq!(value["response"]["content"]["text"], "AP8B");
        assert_eq!(value["request"]["postData"]["text"], "secret-body");
        let timings = &value["timings"];
        assert_eq!(
            value["time"].as_u64().unwrap(),
            timings["wait"].as_u64().unwrap() + timings["receive"].as_u64().unwrap()
        );
    }

    #[test]
    fn sanitizes_duplicate_encoded_query_names_and_userinfo() {
        let output =
            sanitize_url("https://user:pass@example.test/a?%74oken=abc&token=def&safe=yes#secret");
        assert!(!output.contains("abc"));
        assert!(!output.contains("def"));
        assert!(!output.contains("user:pass"));
        assert!(output.contains("safe=yes"));
        assert!(!output.contains("#secret"));
    }

    #[test]
    fn sanitized_exports_cover_common_azure_credential_headers() {
        for name in [
            "x-functions-key",
            "Ocp-Apim-Subscription-Key",
            "x-ms-authorization-auxiliary",
        ] {
            let headers = vec![Header {
                name: name.into(),
                value: "private-value".into(),
            }];
            assert_eq!(
                export_headers(&headers, ExportMode::Sanitized)[0].value,
                "[REDACTED]"
            );
        }
    }

    #[test]
    fn export_atomically_replaces_a_previous_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("capture.har");
        std::fs::write(&path, "old").unwrap();
        export(&path, &[sample()], ExportMode::Sanitized).unwrap();
        let value: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(value["log"]["entries"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn incomplete_capture_sizes_are_not_reported_as_complete_resource_sizes() {
        let mut session = sample();
        session.response.data = b"part".to_vec();
        session.response.total_bytes = 100;
        let full = entry(&session, ExportMode::Full).unwrap();
        assert_eq!(full["response"]["content"]["size"], 100);
        assert_eq!(full["response"]["content"]["_partial"], true);
        session.response_headers.push(Header {
            name: "content-encoding".into(),
            value: "gzip".into(),
        });
        let sanitized = entry(&session, ExportMode::Sanitized).unwrap();
        assert_eq!(sanitized["response"]["content"]["size"], -1);
        assert_eq!(sanitized["response"]["bodySize"], 100);
    }

    #[test]
    fn invalid_request_targets_keep_valid_har_urls_and_explicit_original_targets() {
        let mut session = sample();
        session.url = "/bad?token=private-token".into();
        let sanitized = entry(&session, ExportMode::Sanitized).unwrap();
        assert_eq!(
            sanitized["request"]["url"],
            "http://invalid-request.invalid/"
        );
        assert_eq!(sanitized["_juan"]["invalidRequestTarget"], true);
        assert!(!sanitized.to_string().contains("private-token"));
        let full = entry(&session, ExportMode::Full).unwrap();
        assert_eq!(full["_juan"]["originalRequestTarget"], session.url);
    }
}
