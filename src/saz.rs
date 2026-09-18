use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    time::Instant,
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use quick_xml::{Reader, events::Event};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::{
    capture::{ArchiveInfo, CaptureLimits, CapturedBody, Header, Session, SessionKind, header},
    har::{ExportMode, export_headers, sanitize_url},
};

const HEADER_LIMIT: usize = 64 * 1024;
const METADATA_LIMIT: usize = 512 * 1024;
const DIRECTORY_LIMIT: u64 = 8 * 1024 * 1024;
const FLAG_HTTPS: u64 = 1;
const FLAG_WEBSOCKET: u64 = 262144;
const FLAG_RESPONSE_DROPPED: u64 = 131072;
const FLAG_REQUEST_DROPPED: u64 = 1048576;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub capture: CaptureLimits,
    pub archive_bytes: u64,
    pub entry_bytes: u64,
    pub expanded_bytes: u64,
    pub entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            capture: CaptureLimits::default(),
            archive_bytes: 256 * 1024 * 1024,
            entry_bytes: 32 * 1024 * 1024,
            expanded_bytes: 256 * 1024 * 1024,
            entries: 5000,
        }
    }
}

#[derive(Debug)]
pub struct ImportedArchive {
    pub sessions: Vec<Session>,
    pub warnings: Vec<String>,
}

#[derive(Default)]
struct Parts {
    request: Option<usize>,
    response: Option<usize>,
    metadata: Option<usize>,
    websocket: bool,
}

#[derive(Default)]
struct Metadata {
    flags: BTreeMap<String, String>,
    timers: BTreeMap<String, String>,
    bits: Option<u64>,
    notes: Vec<String>,
}

struct Message {
    headers: Vec<Header>,
    body: CapturedBody,
}

pub fn load(path: &Path, limits: Limits) -> Result<ImportedArchive> {
    let file = File::open(path).with_context(|| format!("Open SAZ {}", path.display()))?;
    read(file, limits)
}

pub fn read<R: Read + Seek>(mut source: R, limits: Limits) -> Result<ImportedArchive> {
    ensure!(
        limits.entries > 0 && limits.capture.sessions > 0,
        "Archive/session limits must be positive"
    );
    ensure!(
        limits.capture.body_bytes > 0
            && limits.capture.total_body_bytes >= limits.capture.body_bytes,
        "Invalid archive body retention limits"
    );
    let count = check_directory(&mut source, limits)?;
    source.rewind()?;
    let mut zip = ZipArchive::new(source).context("Read SAZ ZIP directory")?;
    ensure!(
        zip.len() == count,
        "Duplicate or inconsistent ZIP directory entries"
    );
    ensure!(
        !zip.has_overlapping_files()?,
        "Overlapping ZIP entries are not supported"
    );
    let mut names = BTreeSet::new();
    let mut groups: BTreeMap<u64, Parts> = BTreeMap::new();
    let mut declared_total = 0u64;
    let mut ignored = 0usize;
    for index in 0..zip.len() {
        let entry = zip.by_index_raw(index)?;
        let name = safe_name(entry.name())?;
        ensure!(
            names.insert(name.to_ascii_lowercase()),
            "Duplicate archive entry: {name}"
        );
        ensure!(
            !entry.encrypted(),
            "Password-protected SAZ is not supported; export an unencrypted archive"
        );
        ensure!(
            !entry.is_symlink(),
            "Symbolic links are not allowed in SAZ archives"
        );
        ensure!(
            matches!(
                entry.compression(),
                CompressionMethod::Stored | CompressionMethod::Deflated
            ),
            "Unsupported ZIP compression in {name}; use Stored or Deflate"
        );
        ensure!(
            entry.size() <= limits.entry_bytes,
            "SAZ entry {name} exceeds the entry size limit"
        );
        declared_total = declared_total
            .checked_add(entry.size())
            .context("Expanded ZIP size overflow")?;
        ensure!(
            declared_total <= limits.expanded_bytes,
            "SAZ exceeds the expanded size limit"
        );
        if entry.is_dir() {
            continue;
        }
        let lower = name.to_ascii_lowercase();
        let Some(raw) = lower.strip_prefix("raw/") else {
            continue;
        };
        let Some((number, suffix)) = raw.split_once('_') else {
            ignored += 1;
            continue;
        };
        if !number.bytes().all(|b| b.is_ascii_digit()) || number.is_empty() || raw.contains('/') {
            ignored += 1;
            continue;
        }
        let id: u64 = number.parse().context("SAZ session ID is out of range")?;
        if !matches!(suffix, "c.txt" | "s.txt" | "m.xml" | "w.txt") {
            ignored += 1;
            continue;
        }
        ensure!(
            groups.contains_key(&id) || groups.len() < limits.capture.sessions,
            "SAZ exceeds the session retention limit; split the capture first"
        );
        let parts = groups.entry(id).or_default();
        let slot = match suffix {
            "c.txt" => &mut parts.request,
            "s.txt" => &mut parts.response,
            "m.xml" => &mut parts.metadata,
            "w.txt" => {
                parts.websocket = true;
                continue;
            }
            _ => unreachable!("session suffix was checked"),
        };
        ensure!(
            slot.replace(index).is_none(),
            "Ambiguous files for SAZ session {id}"
        );
        ensure!(
            groups.len() <= limits.capture.sessions,
            "SAZ exceeds the session retention limit; split the capture first"
        );
    }
    ensure!(
        !groups.is_empty(),
        "No supported raw HTTP sessions were found in this SAZ"
    );
    let mut expanded = 0u64;
    let mut retained = 0usize;
    let mut sessions = Vec::new();
    let mut warnings = Vec::new();
    for (id, parts) in groups {
        let request_index = parts
            .request
            .with_context(|| format!("SAZ session {id} has no request file"))?;
        let mut metadata = match parts.metadata {
            Some(index) => parse_metadata(&read_entry(
                &mut zip,
                index,
                METADATA_LIMIT as u64,
                &mut expanded,
                limits,
            )?)?,
            None => Metadata {
                notes: vec![
                    "Session metadata is absent; unavailable timings are not inferred.".into(),
                ],
                ..Default::default()
            },
        };
        if parts.websocket {
            metadata.notes.push("WebSocket message payloads are not imported or re-exported; the HTTP handshake is retained.".into());
        }
        let request_raw = read_entry(
            &mut zip,
            request_index,
            limits.entry_bytes,
            &mut expanded,
            limits,
        )?;
        let (start, request_headers, request_offset) = parse_head(&request_raw)
            .with_context(|| format!("Parse request in SAZ session {id}"))?;
        let (method, target, version) = request_line(&start)?;
        let kind = if method == "CONNECT" {
            SessionKind::Tunnel
        } else if parts.websocket || metadata.bits.is_some_and(|bits| bits & FLAG_WEBSOCKET != 0) {
            SessionKind::WebSocket
        } else {
            SessionKind::Http
        };
        let request_body = parse_body(
            &request_raw[request_offset..],
            &request_headers,
            false,
            limits,
            &mut retained,
        )
        .with_context(|| format!("Read request body in SAZ session {id}"))?;
        let mut request = Message {
            headers: request_headers,
            body: request_body,
        };
        let (status, mut response, response_version) = if let Some(index) = parts.response {
            let raw = read_entry(&mut zip, index, limits.entry_bytes, &mut expanded, limits)?;
            if raw.is_empty() {
                (None, empty_message(), String::new())
            } else {
                let (line, headers, offset) = parse_head(&raw)
                    .with_context(|| format!("Parse response in SAZ session {id}"))?;
                let (protocol, status) = response_line(&line)?;
                let no_body = method == "HEAD"
                    || status < 200
                    || status == 204
                    || status == 304
                    || (method == "CONNECT" && (200..300).contains(&status));
                let body = parse_body(&raw[offset..], &headers, no_body, limits, &mut retained)
                    .with_context(|| format!("Read response body in SAZ session {id}"))?;
                (Some(status), Message { headers, body }, protocol)
            }
        } else {
            (None, empty_message(), String::new())
        };
        restore_message(&mut request, &metadata.flags, "request")?;
        restore_message(&mut response, &metadata.flags, "response")?;
        let url = match metadata.flags.get("x-juan-url") {
            Some(url) => url.clone(),
            None => resolve_url(
                &method,
                &target,
                &request.headers,
                metadata.bits,
                &mut metadata.notes,
            )?,
        };
        ensure!(
            !url.contains(['\r', '\n', '\0']),
            "Invalid recorded request URL"
        );
        let uri = url.parse::<http::Uri>().ok();
        let host = uri
            .as_ref()
            .and_then(http::Uri::host)
            .or_else(|| header(&request.headers, "host"))
            .unwrap_or("")
            .to_owned();
        let path = if method == "CONNECT" {
            target.clone()
        } else {
            uri.as_ref()
                .and_then(http::Uri::path_and_query)
                .map_or(target.clone(), |p| p.to_string())
        };
        let started_at = timestamp(
            metadata.timers.get("ClientBeginRequest"),
            "ClientBeginRequest",
            &mut metadata.notes,
        );
        let ended_at = timestamp(
            metadata.timers.get("ClientDoneResponse"),
            "ClientDoneResponse",
            &mut metadata.notes,
        );
        let headers_at = timestamp(
            metadata.timers.get("GotResponseHeaders"),
            "GotResponseHeaders",
            &mut metadata.notes,
        );
        let duration_ms = optional_number(&metadata.flags, "x-juan-duration-ms")?
            .or_else(|| interval(started_at, ended_at, "duration", &mut metadata.notes));
        let headers_ms = optional_number(&metadata.flags, "x-juan-headers-ms")?.or_else(|| {
            interval(
                started_at,
                headers_at,
                "response-header timing",
                &mut metadata.notes,
            )
        });
        let complete = optional_bool(&metadata.flags, "x-juan-complete")?
            .unwrap_or(status.is_some() && request.body.complete && response.body.complete);
        for (name, body) in [("Request", &request.body), ("Response", &response.body)] {
            if body.truncated() {
                metadata.notes.push(format!(
                    "{name} body is partial: {} of {} bytes retained.",
                    body.data.len(),
                    body.total_bytes
                ));
            }
            if !body.complete {
                metadata
                    .notes
                    .push(format!("{name} was not recorded to completion."));
            }
        }
        if status.is_none() {
            metadata.notes.push("No HTTP response was recorded.".into());
        }
        let protocol = metadata
            .flags
            .get("x-juan-request-version")
            .cloned()
            .unwrap_or(version);
        let response_protocol = metadata
            .flags
            .get("x-juan-response-version")
            .cloned()
            .unwrap_or(response_version);
        let kind = if status == Some(101) {
            SessionKind::WebSocket
        } else {
            kind
        };
        for note in &metadata.notes {
            if warnings.len() < 100 {
                warnings.push(format!("Session {id}: {note}"));
            }
        }
        sessions.push(Session {
            id,
            method,
            url,
            host,
            path,
            protocol,
            response_protocol,
            client: metadata
                .flags
                .get("x-juan-client")
                .cloned()
                .or_else(|| metadata.flags.get("x-clientip").cloned())
                .unwrap_or_default(),
            kind,
            started_at,
            started: Instant::now(),
            duration_ms,
            headers_ms,
            status,
            request_headers: request.headers,
            response_headers: response.headers,
            request: request.body,
            response: response.body,
            error: metadata.flags.get("x-juan-error").cloned(),
            archive: Some(ArchiveInfo {
                original_id: id,
                bit_flags: metadata.bits,
                flags: metadata.flags,
                timers: metadata.timers,
                notes: metadata.notes,
                complete,
            }),
            snapshot_elapsed_ms: duration_ms,
        });
    }
    if ignored > 0 {
        warnings.push(format!(
            "{ignored} unsupported raw archive entries were ignored."
        ));
    }
    Ok(ImportedArchive { sessions, warnings })
}

fn empty_message() -> Message {
    Message {
        headers: Vec::new(),
        body: CapturedBody::default(),
    }
}

fn safe_name(name: &str) -> Result<String> {
    ensure!(
        name.len() <= 1024 && !name.contains(['\0', ':']),
        "Unsafe ZIP entry name"
    );
    let name = name.replace('\\', "/");
    ensure!(!name.starts_with('/'), "Absolute ZIP paths are not allowed");
    ensure!(
        name.trim_end_matches('/')
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".."),
        "Unsafe ZIP traversal path"
    );
    Ok(name)
}

fn read_entry<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    index: usize,
    maximum: u64,
    expanded: &mut u64,
    limits: Limits,
) -> Result<Vec<u8>> {
    let mut entry = zip.by_index(index).context("Open unencrypted SAZ entry")?;
    let maximum = maximum
        .min(limits.entry_bytes)
        .min(limits.expanded_bytes.saturating_sub(*expanded));
    ensure!(
        entry.size() <= maximum,
        "SAZ entry exceeds its size or expanded-data budget"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut entry)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .context("Read SAZ entry and verify its CRC")?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "SAZ decompression limit exceeded"
    );
    ensure!(
        bytes.len() as u64 == entry.size(),
        "ZIP entry length does not match its directory"
    );
    *expanded = expanded
        .checked_add(bytes.len() as u64)
        .context("Expanded SAZ size overflow")?;
    Ok(bytes)
}

// Bound central-directory allocation before passing untrusted metadata to the ZIP library.
fn check_directory<R: Read + Seek>(source: &mut R, limits: Limits) -> Result<usize> {
    let length = source.seek(SeekFrom::End(0))?;
    ensure!(
        length <= limits.archive_bytes && length >= 22,
        "SAZ exceeds the archive size limit or is not a ZIP"
    );
    let tail_len = length.min(65557) as usize;
    source.seek(SeekFrom::End(-(tail_len as i64)))?;
    let mut tail = vec![0; tail_len];
    source.read_exact(&mut tail)?;
    let end = (0..=tail.len() - 22)
        .rev()
        .find(|&i| {
            tail[i..i + 4] == *b"PK\x05\x06"
                && i + 22 + le16(&tail[i + 20..]) as usize == tail.len()
        })
        .context("SAZ has no valid ZIP end-of-directory record")?;
    let end_position = length - tail_len as u64 + end as u64;
    let record = &tail[end..];
    ensure!(
        le16(&record[4..]) == 0 && le16(&record[6..]) == 0,
        "Multi-disk ZIP archives are not supported"
    );
    let mut count = le16(&record[10..]) as u64;
    let mut directory_size = le32(&record[12..]) as u64;
    let mut offset = le32(&record[16..]) as u64;
    if count == u16::MAX as u64 || directory_size == u32::MAX as u64 || offset == u32::MAX as u64 {
        ensure!(end_position >= 20, "Missing ZIP64 locator");
        source.seek(SeekFrom::Start(end_position - 20))?;
        let mut locator = [0; 20];
        source.read_exact(&mut locator)?;
        ensure!(
            &locator[..4] == b"PK\x06\x07" && le32(&locator[4..]) == 0 && le32(&locator[16..]) == 1,
            "Unsupported ZIP64 locator"
        );
        let position = le64(&locator[8..]);
        ensure!(
            position
                .checked_add(56)
                .is_some_and(|p| p <= end_position - 20),
            "Invalid ZIP64 directory offset"
        );
        source.seek(SeekFrom::Start(position))?;
        let mut zip64 = [0; 56];
        source.read_exact(&mut zip64)?;
        ensure!(
            &zip64[..4] == b"PK\x06\x06" && le32(&zip64[16..]) == 0 && le32(&zip64[20..]) == 0,
            "Unsupported ZIP64 directory"
        );
        count = le64(&zip64[32..]);
        ensure!(le64(&zip64[24..]) == count, "Inconsistent ZIP64 file count");
        directory_size = le64(&zip64[40..]);
        offset = le64(&zip64[48..]);
    } else {
        ensure!(
            le16(&record[8..]) as u64 == count,
            "Inconsistent ZIP file count"
        );
    }
    ensure!(
        count <= limits.entries as u64,
        "SAZ exceeds the ZIP entry count limit"
    );
    ensure!(
        directory_size <= DIRECTORY_LIMIT,
        "SAZ ZIP directory exceeds its metadata budget"
    );
    let directory_end = offset
        .checked_add(directory_size)
        .context("ZIP directory offset overflow")?;
    ensure!(
        directory_end <= end_position,
        "Invalid ZIP directory bounds"
    );
    source.seek(SeekFrom::Start(offset))?;
    let mut directory = vec![0; directory_size as usize];
    source.read_exact(&mut directory)?;
    let mut position = 0usize;
    let mut actual_count = 0;
    while position < directory.len() {
        ensure!(
            directory.len() - position >= 46 && &directory[position..position + 4] == b"PK\x01\x02",
            "Invalid ZIP central directory entry"
        );
        let record = &directory[position..];
        position = position
            .checked_add(
                46 + le16(&record[28..]) as usize
                    + le16(&record[30..]) as usize
                    + le16(&record[32..]) as usize,
            )
            .context("ZIP entry size overflow")?;
        ensure!(position <= directory.len(), "Truncated ZIP directory entry");
        actual_count += 1;
        ensure!(
            actual_count <= limits.entries,
            "SAZ ZIP entry count limit exceeded"
        );
    }
    ensure!(
        actual_count as u64 == count,
        "ZIP file count differs from the central directory"
    );
    Ok(actual_count)
}

fn le16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}
fn le32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}
fn le64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().expect("checked ZIP field length"))
}

fn header_text(bytes: &[u8]) -> String {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .unwrap_or_else(|_| bytes.iter().map(|&b| char::from(b)).collect())
}

fn parse_head(raw: &[u8]) -> Result<(String, Vec<Header>, usize)> {
    let head = &raw[..raw.len().min(HEADER_LIMIT + 4)];
    let (end, separator) = if let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") {
        (end, 4)
    } else if let Some(end) = head.windows(2).position(|w| w == b"\n\n") {
        (end, 2)
    } else {
        bail!("HTTP header terminator is missing or exceeds 64 KiB")
    };
    let text = header_text(&head[..end]);
    ensure!(!text.contains('\0'), "NUL in HTTP headers");
    let mut lines = text.split('\n').map(|line| line.trim_end_matches('\r'));
    let start = lines.next().context("Missing HTTP start line")?.to_owned();
    let mut headers: Vec<Header> = Vec::new();
    for line in lines {
        if line.starts_with([' ', '\t']) {
            let last = headers
                .last_mut()
                .context("Header continuation has no previous header")?;
            last.value.push(' ');
            last.value.push_str(line.trim());
            continue;
        }
        ensure!(headers.len() < 512, "Too many HTTP headers");
        let (name, value) = line.split_once(':').context("Malformed HTTP header")?;
        http::HeaderName::from_bytes(name.as_bytes()).context("Invalid HTTP header name")?;
        ensure!(!value.contains('\r'), "Embedded CR in HTTP header");
        headers.push(Header {
            name: name.to_owned(),
            value: value.trim_matches([' ', '\t']).to_owned(),
        });
    }
    Ok((start, headers, end + separator))
}

fn request_line(line: &str) -> Result<(String, String, String)> {
    let mut parts = line.split_whitespace();
    let method = parts.next().context("Missing request method")?;
    http::Method::from_bytes(method.as_bytes()).context("Invalid request method")?;
    let target = parts.next().context("Missing request target")?;
    let version = parts.next().context("Missing request HTTP version")?;
    ensure!(parts.next().is_none(), "Malformed request start line");
    valid_version(version)?;
    Ok((method.to_owned(), target.to_owned(), version.to_owned()))
}

fn response_line(line: &str) -> Result<(String, u16)> {
    let mut parts = line.split_whitespace();
    let version = parts.next().context("Missing response HTTP version")?;
    valid_version(version)?;
    let status: u16 = parts.next().context("Missing response status")?.parse()?;
    ensure!((100..=599).contains(&status), "Invalid response status");
    Ok((version.to_owned(), status))
}

fn valid_version(version: &str) -> Result<()> {
    ensure!(
        matches!(
            version,
            "HTTP/1.0" | "HTTP/1.1" | "HTTP/2" | "HTTP/2.0" | "HTTP/3" | "HTTP/3.0"
        ),
        "Unsupported recorded HTTP version"
    );
    Ok(())
}

fn parse_body(
    raw: &[u8],
    headers: &[Header],
    no_body: bool,
    limits: Limits,
    retained: &mut usize,
) -> Result<CapturedBody> {
    let mut body = CapturedBody::default();
    if no_body && raw.is_empty() {
        body.complete = true;
        return Ok(body);
    }
    let transfer = headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
        .flat_map(|h| h.value.split(','))
        .map(str::trim)
        .collect::<Vec<_>>();
    if !transfer.is_empty() {
        ensure!(
            transfer.len() == 1 && transfer[0].eq_ignore_ascii_case("chunked"),
            "Unsupported recorded transfer coding; only chunked can be decoded"
        );
        let mut position = 0;
        while let Some(end) = raw[position..].windows(2).position(|w| w == b"\r\n") {
            let line = std::str::from_utf8(&raw[position..position + end])
                .context("Invalid chunk size")?;
            let size_text = line.split(';').next().unwrap_or(line).trim();
            ensure!(
                !size_text.is_empty() && size_text.bytes().all(|c| c.is_ascii_hexdigit()),
                "Invalid chunk size"
            );
            let size = usize::from_str_radix(size_text, 16).context("Chunk size overflow")?;
            position += end + 2;
            if size == 0 {
                if raw[position..].starts_with(b"\r\n") {
                    ensure!(
                        position + 2 == raw.len(),
                        "Unexpected data after chunked body"
                    );
                    body.complete = true;
                } else if let Some(end) = raw[position..].windows(4).position(|w| w == b"\r\n\r\n")
                {
                    let mut trailer_message = b"HTTP/1.1 200 OK\r\n".to_vec();
                    trailer_message.extend_from_slice(&raw[position..position + end + 4]);
                    body.trailers = parse_head(&trailer_message)?.1;
                    ensure!(
                        position + end + 4 == raw.len(),
                        "Unexpected data after HTTP trailers"
                    );
                    body.complete = true;
                }
                break;
            }
            let available = raw.len() - position;
            let take = size.min(available);
            retain_body(&mut body, &raw[position..position + take], limits, retained);
            position += take;
            if take != size || raw.len() - position < 2 {
                break;
            }
            ensure!(
                &raw[position..position + 2] == b"\r\n",
                "Malformed chunk delimiter"
            );
            position += 2;
        }
    } else {
        retain_body(&mut body, raw, limits, retained);
        let lengths: Vec<u64> = headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
            .map(|h| h.value.parse().context("Invalid Content-Length"))
            .collect::<Result<_>>()?;
        ensure!(
            lengths.windows(2).all(|values| values[0] == values[1]),
            "Conflicting Content-Length headers"
        );
        if let Some(length) = lengths.first() {
            ensure!(
                raw.len() as u64 <= *length,
                "HTTP body exceeds its declared Content-Length"
            );
            body.complete = raw.len() as u64 == *length;
        } else {
            body.complete = true;
        }
    }
    Ok(body)
}

fn retain_body(body: &mut CapturedBody, bytes: &[u8], limits: Limits, retained: &mut usize) {
    body.total_bytes += bytes.len() as u64;
    let count = bytes
        .len()
        .min(limits.capture.body_bytes.saturating_sub(body.data.len()))
        .min(limits.capture.total_body_bytes.saturating_sub(*retained));
    body.data.extend_from_slice(&bytes[..count]);
    *retained += count;
}

fn resolve_url(
    method: &str,
    target: &str,
    headers: &[Header],
    bits: Option<u64>,
    notes: &mut Vec<String>,
) -> Result<String> {
    if method == "CONNECT" {
        let _: http::uri::Authority = target.parse().context("Invalid CONNECT authority")?;
        return Ok(target.to_owned());
    }
    if target.starts_with("http://") || target.starts_with("https://") {
        return Ok(target.to_owned());
    }
    if let (Some(host), Some(bits)) = (header(headers, "host"), bits) {
        let _: http::uri::Authority = host.parse().context("Invalid recorded Host header")?;
        return Ok(format!(
            "{}://{host}{target}",
            if bits & FLAG_HTTPS != 0 {
                "https"
            } else {
                "http"
            }
        ));
    }
    notes.push(
        "Full URL or transport scheme is unavailable; the original request target is preserved."
            .into(),
    );
    Ok(target.to_owned())
}

fn parse_metadata(bytes: &[u8]) -> Result<Metadata> {
    ensure!(
        bytes.len() <= METADATA_LIMIT,
        "SAZ metadata exceeds its size limit"
    );
    let text = std::str::from_utf8(bytes)
        .context("SAZ XML metadata must be UTF-8")?
        .trim_start_matches('\u{feff}');
    let mut reader = Reader::from_str(text);
    reader.config_mut().check_comments = true;
    let mut metadata = Metadata::default();
    let mut depth = 0usize;
    let mut parents: Vec<String> = Vec::new();
    let mut root_seen = false;
    let mut root_closed = false;
    let mut timers_seen = false;
    let mut ignored = BTreeSet::new();
    loop {
        let event = reader.read_event().context("Parse SAZ XML metadata")?;
        let empty = matches!(&event, Event::Empty(_));
        match event {
            Event::DocType(_) => {
                bail!("DTDs and external entities are not allowed in SAZ metadata")
            }
            Event::Start(element) | Event::Empty(element) => {
                let name = element.local_name().as_ref().to_owned();
                if depth == 0 {
                    ensure!(
                        !root_seen && !root_closed && name == "Session",
                        "SAZ metadata must have one Session root"
                    );
                    root_seen = true;
                }
                let mut attributes = BTreeMap::new();
                for attribute in element.attributes() {
                    let attribute = attribute.context("Invalid XML attribute")?;
                    let key = attribute.key.as_ref().to_owned();
                    let value = attribute
                        .normalized_value(quick_xml::XmlVersion::Explicit1_0)?
                        .into_owned();
                    ensure!(valid_xml_chars(&value), "Invalid XML character in metadata");
                    ensure!(
                        attributes.insert(key, value).is_none(),
                        "Duplicate XML attribute"
                    );
                }
                match name.as_str() {
                    "Session" if depth == 0 => {
                        metadata.bits = attributes
                            .get("BitFlags")
                            .map(|value| value.parse())
                            .transpose()?
                    }
                    "SessionTimers" if depth == 1 => {
                        ensure!(!timers_seen, "Duplicate SessionTimers element");
                        metadata.timers = attributes;
                        timers_seen = true;
                    }
                    "SessionFlag" | "SF"
                        if depth == 2
                            && parents
                                .last()
                                .is_some_and(|parent| parent == "SessionFlags") =>
                    {
                        let key = attributes
                            .remove("N")
                            .context("Session flag has no name")?
                            .to_ascii_lowercase();
                        let key = if let Some(suffix) = key.strip_prefix("x-widdler-") {
                            format!("x-juan-{suffix}")
                        } else {
                            key
                        };
                        let value = attributes
                            .remove("V")
                            .context("Session flag has no value")?;
                        ensure!(
                            !key.is_empty() && metadata.flags.insert(key, value).is_none(),
                            "Duplicate or empty session flag"
                        );
                    }
                    "SessionFlags" if depth == 1 => {}
                    _ => {
                        if !empty || !attributes.is_empty() {
                            ignored.insert(name.clone());
                        }
                    }
                }
                if !empty {
                    parents.push(name);
                    depth += 1;
                    ensure!(depth <= 32, "SAZ XML nesting limit exceeded");
                } else if depth == 0 {
                    root_closed = true;
                }
            }
            Event::End(_) => {
                ensure!(depth > 0, "Unmatched XML close tag");
                depth -= 1;
                parents.pop();
                if depth == 0 {
                    root_closed = true;
                }
            }
            Event::Eof => break,
            Event::Text(value) if depth == 0 => {
                ensure!(
                    value.as_ref().bytes().all(|b| b.is_ascii_whitespace()),
                    "Text outside the Session element"
                );
            }
            Event::Decl(value) => {
                ensure!(
                    !root_seen && value.xml_version()? != quick_xml::XmlVersion::Explicit1_1,
                    "SAZ metadata must use XML 1.0"
                );
            }
            Event::GeneralRef(value) => {
                ensure!(depth > 0, "Entity outside the Session element");
                let reference = value.as_ref();
                if !matches!(reference, "amp" | "lt" | "gt" | "apos" | "quot") {
                    let number = if let Some(hex) = reference.strip_prefix("#x") {
                        u32::from_str_radix(hex, 16).ok()
                    } else {
                        reference
                            .strip_prefix('#')
                            .and_then(|decimal| decimal.parse().ok())
                    };
                    ensure!(
                        number
                            .and_then(char::from_u32)
                            .is_some_and(|character| valid_xml_chars(&character.to_string())),
                        "Unknown or invalid XML entity; external entities are not resolved"
                    );
                }
            }
            Event::CData(_) if depth == 0 => bail!("CDATA outside the Session element"),
            _ => {}
        }
    }
    ensure!(
        root_seen && root_closed && depth == 0,
        "Incomplete SAZ XML metadata"
    );
    if !ignored.is_empty() {
        metadata.notes.push(format!(
            "Additional Fiddler metadata is not interpreted or re-exported: {}.",
            ignored.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    Ok(metadata)
}

fn optional_number(flags: &BTreeMap<String, String>, key: &str) -> Result<Option<u64>> {
    flags
        .get(key)
        .map(|value| {
            value
                .parse()
                .with_context(|| format!("Invalid {key} metadata"))
        })
        .transpose()
}

fn optional_bool(flags: &BTreeMap<String, String>, key: &str) -> Result<Option<bool>> {
    flags
        .get(key)
        .map(|value| match value.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => bail!("Invalid {key} metadata"),
        })
        .transpose()
}

fn restore_message(
    message: &mut Message,
    flags: &BTreeMap<String, String>,
    side: &str,
) -> Result<()> {
    if let Some(value) = flags.get(&format!("x-juan-{side}-headers")) {
        let bytes = STANDARD
            .decode(value)
            .context("Decode preserved HTTP headers")?;
        let headers: Vec<Header> =
            serde_json::from_slice(&bytes).context("Read preserved HTTP headers")?;
        validate_headers(&headers)?;
        message.headers = headers;
    }
    if let Some(value) = flags.get(&format!("x-juan-{side}-trailers")) {
        let bytes = STANDARD
            .decode(value)
            .context("Decode preserved HTTP trailers")?;
        let trailers: Vec<Header> = serde_json::from_slice(&bytes)?;
        validate_headers(&trailers)?;
        message.body.trailers = trailers;
    }
    if let Some(total) = optional_number(flags, &format!("x-juan-{side}-total-bytes"))? {
        ensure!(
            total >= message.body.total_bytes,
            "Preserved body length is shorter than the archived data"
        );
        message.body.total_bytes = total;
    }
    if let Some(complete) = optional_bool(flags, &format!("x-juan-{side}-complete"))? {
        message.body.complete &= complete;
    }
    Ok(())
}

fn timestamp(
    value: Option<&String>,
    name: &str,
    notes: &mut Vec<String>,
) -> Option<OffsetDateTime> {
    let value = value?;
    match OffsetDateTime::parse(value, &Rfc3339) {
        Ok(time) if time.year() > 1601 => Some(time),
        Ok(_) => None,
        Err(_) => {
            notes.push(format!(
                "Invalid {name} timestamp was retained as metadata, not inferred."
            ));
            None
        }
    }
}

fn interval(
    start: Option<OffsetDateTime>,
    end: Option<OffsetDateTime>,
    label: &str,
    notes: &mut Vec<String>,
) -> Option<u64> {
    let milliseconds = (end? - start?).whole_milliseconds();
    match u64::try_from(milliseconds) {
        Ok(value) => Some(value),
        Err(_) => {
            notes.push(format!("Invalid {label}; clock ordering was not guessed."));
            None
        }
    }
}

fn validate_headers(headers: &[Header]) -> Result<()> {
    ensure!(headers.len() <= 512, "Too many recorded headers");
    let mut bytes = 0usize;
    for header in headers {
        http::HeaderName::from_bytes(header.name.as_bytes())
            .context("Invalid recorded header name")?;
        ensure!(
            !header.value.contains(['\r', '\n', '\0']),
            "Control delimiter in recorded header value"
        );
        bytes = bytes
            .checked_add(header.name.len() + header.value.len() + 4)
            .context("Header size overflow")?;
        ensure!(bytes <= HEADER_LIMIT, "Recorded headers exceed 64 KiB");
    }
    Ok(())
}

pub fn export(path: &Path, sessions: &[Session], mode: ExportMode) -> Result<()> {
    crate::archive::atomic_write(path, |file| write(file, sessions, mode))
}

pub fn write<W: Write + Seek>(output: W, sessions: &[Session], mode: ExportMode) -> Result<()> {
    ensure!(!sessions.is_empty(), "There are no sessions to export");
    ensure!(
        sessions.len() <= 1000,
        "SAZ export exceeds the supported session count"
    );
    let mut zip = ZipWriter::new(output);
    zip.set_comment(format!(
        "Juan {} - reconstructed HTTP messages; inspect metadata for partial captures",
        env!("CARGO_PKG_VERSION")
    ))?;
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut expanded = 0u64;
    let mut index = String::from(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Juan session archive</title><style>body{font:14px system-ui;margin:24px;color:#20303b}table{border-collapse:collapse;width:100%}th,td{border:1px solid #dce4e9;padding:6px;text-align:left;vertical-align:top}th{background:#edf5f4}.partial{color:#9a4c0a}</style></head><body><h1>Juan session archive</h1><p>HTTP messages are reconstructed, not packet captures. ",
    );
    index.push_str(if mode == ExportMode::Full { "Sensitive: headers and retained bodies are included." }
        else { "Sanitized: bodies omitted and common credentials redacted. Review URLs and custom headers before sharing." });
    index.push_str("</p><table><thead><tr><th>#</th><th>Result</th><th>Method</th><th>URL</th><th>Bytes</th><th>Time</th><th>Files</th><th>Capture notes</th></tr></thead><tbody>");
    for (position, session) in sessions.iter().enumerate() {
        let id = position + 1;
        let prefix = format!("raw/{id:04}");
        let url = if mode == ExportMode::Sanitized {
            sanitize_url(&session.url)
        } else {
            session.url.clone()
        };
        ensure!(
            !url.chars().any(char::is_whitespace) && !url.contains('\0'),
            "Request URL cannot be represented in a SAZ start line"
        );
        http::Method::from_bytes(session.method.as_bytes())
            .context("Invalid session request method")?;
        let request_headers = export_headers(&session.request_headers, mode);
        let response_headers = export_headers(&session.response_headers, mode);
        let opaque = session.kind != SessionKind::Http;
        let request_data = if mode == ExportMode::Full && !opaque {
            session.request.data.as_slice()
        } else {
            &[]
        };
        let response_data = if mode == ExportMode::Full && !opaque {
            session.response.data.as_slice()
        } else {
            &[]
        };
        ensure!(
            request_data.len() as u64 <= Limits::default().entry_bytes
                && response_data.len() as u64 <= Limits::default().entry_bytes,
            "Retained body exceeds the SAZ entry size limit"
        );
        let request_line = format!(
            "{} {} {}",
            session.method,
            url,
            wire_version(&session.protocol)
        );
        let response_line = session.status.map(|status| {
            format!(
                "{} {} {}",
                wire_version(&session.response_protocol),
                status,
                http::StatusCode::from_u16(status)
                    .ok()
                    .and_then(|s| s.canonical_reason())
                    .unwrap_or("")
            )
        });
        let mut request_wire = Vec::new();
        write_message(
            &mut request_wire,
            &request_line,
            &request_headers,
            request_data,
            false,
            mode,
        )?;
        write_entry(
            &mut zip,
            &format!("{prefix}_c.txt"),
            &request_wire,
            &mut expanded,
            options,
        )?;
        let mut response_wire = Vec::new();
        if let Some(line) = response_line {
            let no_body = session.method == "HEAD"
                || session
                    .status
                    .is_some_and(|s| s < 200 || s == 204 || s == 304)
                || session.kind == SessionKind::Tunnel;
            write_message(
                &mut response_wire,
                &line,
                &response_headers,
                response_data,
                no_body,
                mode,
            )?;
        }
        write_entry(
            &mut zip,
            &format!("{prefix}_s.txt"),
            &response_wire,
            &mut expanded,
            options,
        )?;
        let metadata =
            write_metadata(id, session, mode, &url, &request_headers, &response_headers)?;
        ensure!(
            metadata.len() <= METADATA_LIMIT,
            "Generated SAZ metadata exceeds the size limit"
        );
        write_entry(
            &mut zip,
            &format!("{prefix}_m.xml"),
            metadata.as_bytes(),
            &mut expanded,
            options,
        )?;
        let note = if mode == ExportMode::Sanitized {
            "Bodies omitted"
        } else if opaque {
            "Opaque payload not retained"
        } else if session.request.truncated() || session.response.truncated() {
            "Truncated body"
        } else if !session.capture_complete() {
            "Incomplete session"
        } else {
            ""
        };
        use std::fmt::Write as _;
        write!(
            index,
            "<tr><td>{id}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><a href='{prefix}_c.txt'>C</a>&nbsp;<a href='{prefix}_s.txt'>S</a>&nbsp;<a href='{prefix}_m.xml'>M</a></td><td class='partial'>{}</td></tr>",
            session.status.map_or("-".into(), |s| s.to_string()),
            escape(&session.method),
            escape(&url),
            session.response.total_bytes,
            session
                .elapsed_ms()
                .map_or("Not recorded".into(), |ms| format!("{ms} ms")),
            escape(note)
        )?;
    }
    index.push_str("</tbody></table></body></html>");
    write_entry(
        &mut zip,
        "_index.htm",
        index.as_bytes(),
        &mut expanded,
        options,
    )?;
    write_entry(&mut zip, "[Content_Types].xml",
        br#"<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="txt" ContentType="application/octet-stream"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="htm" ContentType="text/html"/></Types>"#,
        &mut expanded, options)?;
    let mut output = zip.finish().context("Finish SAZ archive")?;
    ensure!(
        output.stream_position()? <= Limits::default().archive_bytes,
        "Generated SAZ exceeds the archive size limit"
    );
    Ok(())
}

fn write_entry<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    name: &str,
    data: &[u8],
    expanded: &mut u64,
    options: SimpleFileOptions,
) -> Result<()> {
    let limits = Limits::default();
    ensure!(
        data.len() as u64 <= limits.entry_bytes,
        "Generated SAZ entry exceeds the size limit"
    );
    *expanded = expanded
        .checked_add(data.len() as u64)
        .context("SAZ output size overflow")?;
    ensure!(
        *expanded <= limits.expanded_bytes,
        "Generated SAZ exceeds the expanded size limit"
    );
    zip.start_file(name, options)?;
    zip.write_all(data)?;
    Ok(())
}

fn wire_version(version: &str) -> &str {
    if version == "HTTP/1.0" {
        "HTTP/1.0"
    } else {
        "HTTP/1.1"
    }
}

fn write_message(
    writer: &mut impl Write,
    start: &str,
    headers: &[Header],
    body: &[u8],
    no_body: bool,
    mode: ExportMode,
) -> Result<()> {
    validate_headers(headers)?;
    ensure!(
        start.len() <= HEADER_LIMIT,
        "HTTP start line exceeds the archive header limit"
    );
    let mut wire_headers = Vec::new();
    write!(wire_headers, "{start}\r\n")?;
    for field in headers {
        if field.name.eq_ignore_ascii_case("transfer-encoding")
            || field.name.eq_ignore_ascii_case("trailer")
            || (!no_body && field.name.eq_ignore_ascii_case("content-length"))
            || (mode == ExportMode::Sanitized
                && field.name.eq_ignore_ascii_case("content-encoding"))
        {
            continue;
        }
        write!(wire_headers, "{}: {}\r\n", field.name, field.value)?;
    }
    if !no_body {
        write!(wire_headers, "Content-Length: {}\r\n", body.len())?;
    }
    wire_headers.extend_from_slice(b"\r\n");
    ensure!(
        wire_headers.len() <= HEADER_LIMIT,
        "HTTP headers exceed the archive header limit"
    );
    writer.write_all(&wire_headers)?;
    writer.write_all(body)?;
    Ok(())
}

fn write_metadata(
    id: usize,
    session: &Session,
    mode: ExportMode,
    url: &str,
    request_headers: &[Header],
    response_headers: &[Header],
) -> Result<String> {
    let mut flags = if mode == ExportMode::Full {
        session
            .archive
            .as_ref()
            .map_or_else(BTreeMap::new, |a| a.flags.clone())
    } else {
        BTreeMap::new()
    };
    flags.retain(|name, _| !name.starts_with("x-juan-") && !name.starts_with("x-widdler-"));
    let mut timers = if mode == ExportMode::Full {
        session
            .archive
            .as_ref()
            .map_or_else(BTreeMap::new, |a| a.timers.clone())
    } else {
        BTreeMap::new()
    };
    if let Some(started) = session.started_at {
        timers
            .entry("ClientBeginRequest".into())
            .or_insert(started.format(&Rfc3339)?);
        if let Some(duration) = session.duration_ms {
            let duration: i64 = duration
                .try_into()
                .context("Session duration is out of range")?;
            let ended = started
                .checked_add(Duration::milliseconds(duration))
                .context("Session timestamp overflow")?;
            timers
                .entry("ClientDoneResponse".into())
                .or_insert(ended.format(&Rfc3339)?);
        }
        if let Some(headers) = session.headers_ms {
            let headers: i64 = headers
                .try_into()
                .context("Header timing is out of range")?;
            let at = started
                .checked_add(Duration::milliseconds(headers))
                .context("Header timestamp overflow")?;
            timers
                .entry("GotResponseHeaders".into())
                .or_insert(at.format(&Rfc3339)?);
        }
    }
    flags.insert("x-juan-version".into(), env!("CARGO_PKG_VERSION").into());
    flags.insert("x-juan-url".into(), url.into());
    flags.insert("x-juan-request-version".into(), session.protocol.clone());
    flags.insert(
        "x-juan-response-version".into(),
        session.response_protocol.clone(),
    );
    flags.insert(
        "x-juan-complete".into(),
        session.capture_complete().to_string(),
    );
    flags.insert("x-juan-original-session-id".into(), session.id.to_string());
    if let Some(ms) = session.elapsed_ms() {
        flags.insert("x-juan-duration-ms".into(), ms.to_string());
    }
    if let Some(ms) = session.headers_ms {
        flags.insert("x-juan-headers-ms".into(), ms.to_string());
    }
    if mode == ExportMode::Full && !session.client.is_empty() {
        flags.insert("x-juan-client".into(), session.client.clone());
    }
    if let Some(error) = &session.error {
        flags.insert(
            "x-juan-error".into(),
            if mode == ExportMode::Full {
                error.clone()
            } else {
                "Proxy error; details omitted".into()
            },
        );
    }
    let mut bits = session
        .archive
        .as_ref()
        .and_then(|a| a.bit_flags)
        .unwrap_or(0);
    if session.url.starts_with("https://") {
        bits |= FLAG_HTTPS;
    }
    if session.kind == SessionKind::Tunnel {
        bits |= FLAG_HTTPS;
    }
    if session.kind == SessionKind::WebSocket {
        bits |= FLAG_WEBSOCKET;
    }
    for (name, body, headers, dropped) in [
        (
            "request",
            &session.request,
            request_headers,
            FLAG_REQUEST_DROPPED,
        ),
        (
            "response",
            &session.response,
            response_headers,
            FLAG_RESPONSE_DROPPED,
        ),
    ] {
        flags.insert(
            format!("x-juan-{name}-headers"),
            STANDARD.encode(serde_json::to_vec(headers)?),
        );
        flags.insert(
            format!("x-juan-{name}-trailers"),
            STANDARD.encode(serde_json::to_vec(&export_headers(&body.trailers, mode))?),
        );
        flags.insert(
            format!("x-juan-{name}-total-bytes"),
            body.total_bytes.to_string(),
        );
        flags.insert(format!("x-juan-{name}-complete"), body.complete.to_string());
        if body.truncated() || mode == ExportMode::Sanitized || session.kind != SessionKind::Http {
            bits |= dropped;
        }
    }
    let note = "Juan: HTTP headers/framing reconstructed; original headers and body retention state are preserved in x-juan-* flags.";
    let previous = flags.get("ui-comments").cloned().unwrap_or_default();
    flags.insert(
        "ui-comments".into(),
        if previous.contains(note) {
            previous
        } else if previous.is_empty() {
            note.into()
        } else {
            format!("{previous}\n{note}")
        },
    );
    if mode == ExportMode::Sanitized {
        flags.insert("x-juan-sanitized".into(), "true".into());
    }
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<Session SID=\"{id}\" BitFlags=\"{bits}\">\r\n  <SessionTimers"
    );
    use std::fmt::Write as _;
    for (name, value) in &timers {
        ensure!(
            name.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "Invalid timing attribute name"
        );
        ensure!(
            valid_xml_chars(value),
            "Invalid XML character in timing metadata"
        );
        write!(xml, " {name}=\"{}\"", escape(value))?;
    }
    xml.push_str(" />\r\n  <SessionFlags>\r\n");
    for (name, value) in &flags {
        ensure!(
            valid_xml_chars(name) && valid_xml_chars(value),
            "Invalid XML control character in session metadata"
        );
        write!(
            xml,
            "    <SessionFlag N=\"{}\" V=\"{}\" />\r\n",
            escape(name),
            escape(value)
        )?;
    }
    xml.push_str("  </SessionFlags>\r\n</Session>\r\n");
    Ok(xml)
}

fn valid_xml_chars(value: &str) -> bool {
    value.chars().all(|c| {
        c == '\t' || c == '\r' || c == '\n' || (c >= '\u{20}' && c != '\u{fffe}' && c != '\u{ffff}')
    })
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('\r', "&#13;")
        .replace('\n', "&#10;")
        .replace('\t', "&#9;")
}
