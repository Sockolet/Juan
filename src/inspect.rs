use std::{
    fmt::Write as _,
    io::{Read, Write},
};

use anyhow::{Context, Result, bail, ensure};

use crate::capture::{Notice, Session, SessionKind, Side, header};

pub const PREVIEW_LIMIT: usize = 2 * 1024 * 1024;
pub const DECODE_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inspector {
    Headers,
    Text,
    Json,
    Hex,
}

pub fn bytes_label(bytes: u64) -> String {
    match bytes {
        0..1024 => format!("{bytes} B"),
        1024..1_048_576 => format!("{:.1} KB", bytes as f64 / 1024.0),
        _ => format!("{:.1} MB", bytes as f64 / 1_048_576.0),
    }
}

pub fn decode_body(session: &Session, side: Side, limit: usize) -> Result<Vec<u8>> {
    let mut data = session.body(side).data.clone();
    ensure!(
        data.len() <= limit,
        "Body exceeds the decoded preview limit"
    );
    if let Some(evidence) = session.archive.as_ref().and_then(|a| a.har.as_ref())
        && evidence.body(side).representation != crate::har_import::Representation::Wire {
        return Ok(data);
    }
    let encoding = header(session.headers(side), "content-encoding").unwrap_or("");
    for encoding in encoding.split(',').rev().map(str::trim) {
        data = match encoding.to_ascii_lowercase().as_str() {
            "" | "identity" => data,
            "gzip" | "x-gzip" => {
                read_bounded(flate2::read::MultiGzDecoder::new(data.as_slice()), limit)?
            }
            "deflate" => read_bounded(flate2::read::ZlibDecoder::new(data.as_slice()), limit)?,
            "br" => read_bounded(brotli::Decompressor::new(data.as_slice(), 4096), limit)?,
            _ => bail!(
                "Unsupported content encoding '{encoding}'; inspect the original bytes in Hex"
            ),
        };
    }
    Ok(data)
}

fn read_bounded(reader: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut output)
        .context("Decode body (it may be incomplete)")?;
    ensure!(
        output.len() <= limit,
        "Decoded body exceeds the {} preview limit",
        bytes_label(limit as u64)
    );
    Ok(output)
}

pub fn render(session: &Session, side: Side, inspector: Inspector) -> String {
    if inspector == Inspector::Headers {
        return render_headers(session, side);
    }
    if session.kind == SessionKind::Tunnel {
        return String::from(
            "CONNECT connection\r\n\r\nThis row describes the connection, not an HTTP message body.\r\n\
             Decrypted HTTP requests appear as separate sessions.\r\n\
             With decryption off, only tunnel metadata and byte counts are available.\r\n\
             See Headers or Diagnostics for TLS handshake failures.",
        );
    }
    if session.kind == SessionKind::WebSocket {
        return String::from(
            "WebSocket upgrade\r\n\r\nThe HTTP/1.1 handshake is captured in Headers.\r\n\
             WebSocket bytes are relayed without modification; individual frames are not decoded.",
        );
    }
    let body = session.body(side);
    let har = session.archive.as_ref().and_then(|a| a.har.as_ref());
    if body.data.is_empty()
        && let Some(evidence) = har {
            let mut text = crate::har_import::describe(session, evidence, side);
            if side == Side::Request && !evidence.params.is_empty() {
                text.push_str("\r\nStructured form parameters (not original body bytes):\r\n");
                text.push_str(&pretty_json(&evidence.params).unwrap_or_else(|error|
                    format!("{error}; use full HAR export for structured parameters.")));
            }
            return text;
    }
    if body.data.is_empty() {
        return if session.archive.as_ref().is_some_and(|archive| {
            archive
                .flags
                .get("x-juan-sanitized")
                .is_some_and(|value| value == "true")
        }) {
            String::from("Body omitted by sanitized archive export.")
        } else if body.total_bytes > 0 {
            format!(
                "{} transferred; no body bytes were retained. The capture or archive retention budget may have been reached.",
                bytes_label(body.total_bytes)
            )
        } else if body.complete {
            String::from("No body.")
        } else if session.is_settled() {
            String::from(
                "The session ended before this body was captured. See Headers or Diagnostics for details.",
            )
        } else {
            String::from("Waiting for body data...")
        };
    }
    let mut prefix = har.map(|e| crate::har_import::describe(session, e, side)).unwrap_or_default();
    if har.is_some() {
        prefix.push_str("\r\n");
    } else if body.truncated() {
        let _ = write!(
            prefix,
            "[TRUNCATED: retained {} of {} transferred]\r\n\r\n",
            bytes_label(body.data.len() as u64),
            bytes_label(body.total_bytes)
        );
    } else if !body.complete {
        prefix.push_str(if session.is_settled() {
            "[INCOMPLETE: the session ended before this body finished]\r\n\r\n"
        } else {
            "[IN PROGRESS: this body is not complete]\r\n\r\n"
        });
    }
    if inspector == Inspector::Hex {
        prefix.push_str(&hex_dump(&body.data, 64 * 1024));
        return prefix;
    }
    let decoded = match decode_body(session, side, PREVIEW_LIMIT) {
        Ok(decoded) => decoded,
        Err(error) => {
            return format!("{prefix}{error:#}\r\n\r\nUse Hex for the captured wire bytes.");
        }
    };
    let text = match std::str::from_utf8(&decoded) {
        Ok(text) => text.trim_start_matches('\u{feff}'),
        Err(_) => {
            return format!(
                "{prefix}This body is not UTF-8 text. Use Hex to inspect its original bytes."
            );
        }
    };
    match inspector {
        Inspector::Json => match serde_json::from_str::<serde_json::Value>(text) {
            Ok(json) => match pretty_json(&json) {
                Ok(pretty) => prefix.push_str(&pretty),
                Err(error) => {
                    let _ = write!(prefix, "{error:#}\r\n\r\nUse Text or Hex instead.");
                }
            },
            Err(error) => {
                let _ = write!(
                    prefix,
                    "Not valid, complete JSON: {error}\r\n\r\nUse Text for the original content."
                );
            }
        },
        Inspector::Text => prefix.push_str(text),
        _ => unreachable!(),
    }
    prefix
        .replace('\0', "\\0")
        .replace("\r\n", "\n")
        .replace('\n', "\r\n")
}

fn pretty_json(value: &impl serde::Serialize) -> Result<String> {
    struct Limited(Vec<u8>);
    impl Write for Limited {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0.len() + bytes.len() > PREVIEW_LIMIT {
                return Err(std::io::Error::other(
                    "Formatted JSON exceeds the preview limit",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Limited(Vec::new());
    serde_json::to_writer_pretty(&mut writer, value)?;
    Ok(String::from_utf8(writer.0)?)
}

fn render_headers(session: &Session, side: Side) -> String {
    let mut text = if side == Side::Request {
        format!(
            "{} {} {}\r\n",
            session.method, session.path, session.protocol
        )
    } else {
        let status = session.status.map_or(
            if session.is_settled() {
                "(not recorded)".into()
            } else {
                "(pending)".into()
            },
            |s| s.to_string(),
        );
        let reason = session
            .archive.as_ref().and_then(|a| a.har.as_ref()).map(|h| h.status_text.as_str())
            .or_else(|| session.status
                .and_then(|s| http::StatusCode::from_u16(s).ok())
                .and_then(|s| s.canonical_reason()))
            .unwrap_or("");
        format!("{} {status} {reason}\r\n", session.response_protocol)
    };
    for header in session.headers(side) {
        let _ = write!(text, "{}: {}\r\n", header.name, header.value);
    }
    let trailers = &session.body(side).trailers;
    if !trailers.is_empty() {
        text.push_str("\r\n--- Trailers ---\r\n");
        for trailer in trailers {
            let _ = write!(text, "{}: {}\r\n", trailer.name, trailer.value);
        }
    }
    if let Some(error) = &session.error {
        let origin = if session.archive.as_ref().is_some_and(|a| a.har.is_some()) {
            "HAR source diagnostic"
        } else { "Juan diagnostic" };
        let _ = write!(text, "\r\n--- {origin} ---\r\n{error}\r\n");
    }
    if let Some(evidence) = session.archive.as_ref().and_then(|a| a.har.as_ref()) {
        text.push_str("\r\n");
        text.push_str(&crate::har_import::describe(session, evidence, side));
    }
    text.replace('\0', "\\0")
}

pub fn hex_dump(bytes: &[u8], limit: usize) -> String {
    let mut output = String::new();
    for (index, row) in bytes[..bytes.len().min(limit)].chunks(16).enumerate() {
        let _ = write!(output, "{:08X}  ", index * 16);
        for column in 0..16 {
            if column == 8 {
                output.push(' ');
            }
            if let Some(byte) = row.get(column) {
                let _ = write!(output, "{byte:02X} ");
            } else {
                output.push_str("   ");
            }
        }
        output.push_str(" |");
        for &byte in row {
            output.push(if byte.is_ascii_graphic() || byte == b' ' {
                char::from(byte)
            } else {
                '.'
            });
        }
        output.push_str("|\r\n");
    }
    if bytes.len() > limit {
        let _ = write!(
            output,
            "\r\n[Hex preview limited to {}; full retained bytes are available in full HAR export.]",
            bytes_label(limit as u64)
        );
    }
    output
}

pub fn render_timing(session: &Session) -> String {
    if let Some(evidence) = session.archive.as_ref().and_then(|a| a.har.as_ref()) {
        let mut text = format!(
            "HAR SOURCE SESSION #{}\r\nCreator: {} {}\r\nBrowser: {:?}\r\nServer: {}\r\nConnection: {}\r\nTotal: {} ms (-1 = unknown)\r\nRecorded browser timings, not importer measurements:\r\n",
            session.archive.as_ref().unwrap().original_id, evidence.creator.name,
            evidence.creator.version, evidence.browser, evidence.server_ip,
            evidence.connection, evidence.time,
        );
        for (name, value) in &evidence.timings {
            let _ = write!(text, "{name}: {value} ms\r\n");
        }
        text.push_str(&crate::har_import::describe(session, evidence, Side::Request));
        text.push_str(&crate::har_import::describe(session, evidence, Side::Response));
        for note in &session.archive.as_ref().unwrap().notes {
            let _ = write!(text, "\r\nNOTE: {note}\r\n");
        }
        return text;
    }
    let unknown = if session.archive.is_some() {
        "not recorded"
    } else {
        "waiting"
    };
    let headers = session
        .headers_ms
        .map_or(unknown.to_owned(), |ms| format!("{ms} ms"));
    let receive = session
        .headers_ms
        .zip(session.elapsed_ms())
        .map(|(headers, elapsed)| elapsed.saturating_sub(headers));
    let mut output = format!(
        "SESSION #{}\r\n\r\n{}\r\n{}\r\n\r\n\
         Started (UTC)        {}\r\nClient endpoint      {}\r\n\
         Client protocol      {}\r\nUpstream protocol    {}\r\n\r\n\
         Response headers     {}\r\nBody / tunnel        {}\r\n\
         Total elapsed        {}{}\r\n\r\n\
         Request transferred  {}\r\nResponse transferred {}\r\n\
         Retained request     {}\r\nRetained response    {}\r\n\r\n\
         Measurement notes\r\n\
         -----------------\r\n\
         Response headers measures from receipt of the request headers to\r\n\
         receipt of the upstream response headers. It includes upload time.\r\n\
         Body time includes backpressure from the client.\r\n\
         CONNECT and WebSocket totals include the tunnel lifetime.\r\n\
         DNS, TCP, and TLS phases are not individually instrumented.\r\n\
         HTTP headers are reconstructed, not a byte-for-byte packet capture.\r\n",
        session.id,
        session.method,
        session.url,
        session
            .started_at
            .map_or("not recorded".into(), |at| at.to_string()),
        session.client,
        session.protocol,
        session.response_protocol,
        headers,
        receive.map_or(unknown.to_owned(), |ms| format!("{ms} ms")),
        session
            .elapsed_ms()
            .map_or("not recorded".into(), |ms| format!("{ms} ms")),
        if !session.is_settled() {
            " (in progress)"
        } else {
            ""
        },
        bytes_label(session.request.total_bytes),
        bytes_label(session.response.total_bytes),
        bytes_label(session.request.data.len() as u64),
        bytes_label(session.response.data.len() as u64),
    );
    if let Some(archive) = &session.archive {
        let _ = write!(
            output,
            "\r\nSAZ SOURCE SESSION #{}\r\nTimings are recorded archive values, not measurements made during import.\r\n",
            archive.original_id
        );
        for note in &archive.notes {
            let _ = write!(output, "\r\nNOTE: {note}\r\n");
        }
        if !archive.flags.is_empty() {
            output.push_str("\r\nArchive session flags\r\n---------------------\r\n");
            for (name, value) in &archive.flags {
                if !name.starts_with("x-juan-") {
                    let _ = write!(output, "{name}: {value}\r\n");
                }
            }
        }
    }
    output
}

pub fn render_notices(notices: &[Notice]) -> String {
    if notices.is_empty() {
        return String::from(
            "No diagnostics.\r\n\r\nProxy errors and configuration changes appear here.\r\nOnly the most recent 100 messages are retained.",
        );
    }
    let mut output = String::new();
    for notice in notices.iter().rev() {
        let _ = write!(
            output,
            "{:02}:{:02}:{:02} UTC  {}\r\n\r\n",
            notice.time.hour(),
            notice.time.minute(),
            notice.time.second(),
            notice.message
        );
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CaptureStore, Header};

    pub fn session() -> Session {
        let store = CaptureStore::default();
        let id = store.begin(
            &http::Method::GET,
            &"https://example.test/".parse().unwrap(),
            http::Version::HTTP_11,
            &http::HeaderMap::new(),
            "127.0.0.1:1".parse().unwrap(),
        );
        store.get(id.unwrap()).unwrap()
    }

    #[test]
    fn decodes_gzip_without_trusting_the_expanded_size() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&vec![b'x'; 8192]).unwrap();
        let mut session = session();
        session.response.data = encoder.finish().unwrap();
        session.response_headers.push(Header {
            name: "content-encoding".into(),
            value: "gzip".into(),
        });
        assert!(decode_body(&session, Side::Response, 1024).is_err());
        assert_eq!(
            decode_body(&session, Side::Response, 8192).unwrap().len(),
            8192
        );
    }

    #[test]
    fn hex_is_bounded_and_handles_binary() {
        let dump = hex_dump(&[0, 255, b'A', b'\n'], 3);
        assert!(dump.contains("00 FF 41"));
        assert!(dump.contains("|..A|"));
        assert!(dump.contains("limited"));
    }

    #[test]
    fn malformed_json_is_reported_and_nuls_are_visible() {
        let mut session = session();
        session.response.data = b"{bad\0".to_vec();
        assert!(render(&session, Side::Response, Inspector::Json).contains("Not valid"));
        assert!(render(&session, Side::Response, Inspector::Text).contains("\\0"));
    }

    #[test]
    fn finished_failures_are_not_presented_as_still_waiting() {
        let mut session = session();
        session.duration_ms = Some(12);
        session.error = Some("Disconnected".into());
        assert!(render(&session, Side::Response, Inspector::Text).contains("session ended"));
        session.response.data = b"partial".to_vec();
        session.response.total_bytes = 7;
        assert!(render(&session, Side::Response, Inspector::Text).starts_with("[INCOMPLETE"));
    }
}
