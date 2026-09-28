use std::{
    io::{Cursor, Write},
    path::PathBuf,
};

use http::{HeaderMap, Method, Version};
use juan::{
    capture::{CaptureLimits, CaptureStore, Header, SessionKind, Side, header},
    har::{self, ExportMode},
    inspect::{self, Inspector},
    saz::{self, Limits},
};
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("fiddler-reference.saz")
}

fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut output = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut output);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, bytes) in entries {
            zip.start_file(*name, options).unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap();
    }
    output.into_inner()
}

fn minimal(extra: Option<(&str, &[u8])>) -> Vec<u8> {
    let mut entries: Vec<(&str, &[u8])> = vec![
        (
            "raw/1_c.txt",
            b"GET https://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n",
        ),
        (
            "raw/1_s.txt",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        ),
    ];
    if let Some(extra) = extra {
        entries.push(extra);
    }
    archive(&entries)
}
#[test]
fn renamed_saz_uses_the_same_bounded_loader() {
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    for name in ["capture.zip", "capture", "capture.unknown"] {
        let path = dir.path().join(name);
        std::fs::write(&path, minimal(None)).unwrap();
        let imported = juan::archive::load(&path, Limits::default()).unwrap();
        assert_eq!(imported.sessions.len(), 1);
        assert_eq!(imported.sessions[0].response.data, b"hello");
        std::fs::write(&path, b"not a ZIP archive").unwrap();
        assert!(juan::archive::load(&path, Limits::default()).is_err());
    }
}

#[test]
fn renamed_har_is_detected_by_content_and_saz_extension_is_never_sniffed() {
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let har = include_bytes!("fixtures/har/chrome.har");
    for name in ["capture.json", "capture", "capture.txt"] {
        let path = dir.path().join(name);
        std::fs::write(&path, har).unwrap();
        assert!(
            !juan::archive::load(&path, Limits::default())
                .unwrap()
                .sessions
                .is_empty()
        );
    }
    let path = dir.path().join("bom.json");
    std::fs::write(&path, include_bytes!("fixtures/har/utf8-bom.har")).unwrap();
    assert!(juan::archive::load(&path, Limits::default()).is_ok());
    let path = dir.path().join("capture.saz");
    std::fs::write(&path, har).unwrap();
    let error = juan::archive::load(&path, Limits::default()).unwrap_err();
    assert!(format!("{error:#}").contains("ZIP"));
}

fn encode(sessions: &[juan::capture::Session], mode: ExportMode) -> Vec<u8> {
    let mut output = Cursor::new(Vec::new());
    saz::write(&mut output, sessions, mode).unwrap();
    output.into_inner()
}

#[test]
fn reads_real_fiddler_generated_synthetic_fixture_with_binary_and_timings() {
    let archive = saz::load(&fixture(), Limits::default()).unwrap();
    assert_eq!(archive.sessions.len(), 3);
    assert!(archive.warnings.is_empty(), "{:?}", archive.warnings);
    let first = &archive.sessions[0];
    assert_eq!(first.method, "GET");
    assert_eq!(first.url, "https://example.test/fixture?kind=saz");
    assert_eq!(first.status, Some(200));
    assert_eq!(
        first.response.data,
        br#"{"producer":"Fiddler","synthetic":true}"#
    );
    assert_eq!(first.duration_ms, Some(25));
    assert_eq!(first.headers_ms, Some(10));
    assert_eq!(first.started_at.unwrap().year(), 2026);
    assert!(first.capture_complete());
    let second = &archive.sessions[1];
    assert_eq!(second.request.data, [0, 1, 255, 13, 10, 83, 65, 90]);
    assert_eq!(
        header(&second.response_headers, "Content-Encoding"),
        Some("gzip")
    );
    assert_eq!(
        inspect::decode_body(second, Side::Response, 1024).unwrap(),
        second.request.data
    );
    let head = &archive.sessions[2];
    assert_eq!(head.method, "HEAD");
    assert_eq!(
        header(&head.response_headers, "Content-Length"),
        Some("4096")
    );
    assert!(head.response.data.is_empty() && head.response.complete);
}

#[test]
fn older_widdler_archives_restore_metadata_under_the_juan_namespace() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("legacy-v02.saz");
    let legacy = saz::load(&path, Limits::default()).unwrap();
    let reference = saz::load(&fixture(), Limits::default()).unwrap();
    assert_eq!(legacy.sessions.len(), reference.sessions.len());
    for (old, expected) in legacy.sessions.iter().zip(&reference.sessions) {
        assert_eq!(old.url, expected.url);
        assert_eq!(old.request_headers, expected.request_headers);
        assert_eq!(old.response_headers, expected.response_headers);
        assert_eq!(old.request.data, expected.request.data);
        assert_eq!(old.response.data, expected.response.data);
        assert_eq!(old.started_at, expected.started_at);
        assert_eq!(old.duration_ms, expected.duration_ms);
        let flags = &old.archive.as_ref().unwrap().flags;
        assert_eq!(
            flags.get("x-juan-version").map(String::as_str),
            Some("0.2.0")
        );
        assert!(!flags.keys().any(|key| key.starts_with("x-widdler-")));
    }
    let encoded = encode(&legacy.sessions, ExportMode::Full);
    let current = saz::read(Cursor::new(encoded), Limits::default()).unwrap();
    assert_eq!(
        current.sessions[0].archive.as_ref().unwrap().flags["x-juan-version"],
        env!("CARGO_PKG_VERSION")
    );
}

#[test]
fn ambiguous_legacy_and_juan_metadata_is_rejected_instead_of_overwritten() {
    let xml = br#"<Session><SessionFlags><SessionFlag N="x-widdler-duration-ms" V="5"/><SessionFlag N="x-juan-duration-ms" V="10"/></SessionFlags></Session>"#;
    assert!(
        saz::read(
            Cursor::new(minimal(Some(("raw/1_m.xml", xml)))),
            Limits::default()
        )
        .is_err()
    );
}

#[test]
fn full_round_trip_preserves_headers_encoded_bodies_urls_and_known_times() {
    let original = saz::load(&fixture(), Limits::default()).unwrap().sessions;
    let encoded = encode(&original, ExportMode::Full);
    let decoded = saz::read(Cursor::new(&encoded), Limits::default())
        .unwrap()
        .sessions;
    for (left, right) in original.iter().zip(&decoded) {
        assert_eq!(left.url, right.url);
        assert_eq!(left.method, right.method);
        assert_eq!(left.request_headers, right.request_headers);
        assert_eq!(left.response_headers, right.response_headers);
        assert_eq!(left.request.data, right.request.data);
        assert_eq!(left.response.data, right.response.data);
        assert_eq!(left.started_at, right.started_at);
        assert_eq!(left.duration_ms, right.duration_ms);
        assert_eq!(left.headers_ms, right.headers_ms);
    }
    let mut zip = ZipArchive::new(Cursor::new(encoded)).unwrap();
    assert!(zip.by_name("[Content_Types].xml").is_ok());
    let mut index = String::new();
    use std::io::Read;
    zip.by_name("_index.htm")
        .unwrap()
        .read_to_string(&mut index)
        .unwrap();
    assert!(index.contains("</head>"));
    for id in 1..=3 {
        for suffix in ["c.txt", "s.txt", "m.xml"] {
            let name = format!("raw/{id:04}_{suffix}");
            assert!(index.contains(&format!("href='{name}'")));
            assert!(zip.by_name(&name).is_ok());
        }
    }
}

#[test]
fn missing_metadata_is_unknown_not_now_and_archive_sessions_do_not_look_live() {
    let loaded = saz::read(Cursor::new(minimal(None)), Limits::default()).unwrap();
    let session = &loaded.sessions[0];
    assert!(session.started_at.is_none());
    assert!(session.elapsed_ms().is_none());
    assert!(session.is_settled());
    assert!(session.capture_complete());
    assert!(inspect::render_timing(session).contains("not recorded"));
    assert!(har::write_har(Vec::new(), &loaded.sessions, ExportMode::Full).is_err());
    let roundtrip = saz::read(
        Cursor::new(encode(&loaded.sessions, ExportMode::Full)),
        Limits::default(),
    )
    .unwrap();
    assert!(roundtrip.sessions[0].started_at.is_none());
    assert!(roundtrip.sessions[0].duration_ms.is_none());
}

#[test]
fn precise_original_timer_attributes_survive_round_trip() {
    let xml = br#"<Session BitFlags="1"><SessionTimers ClientBeginRequest="2026-09-17T10:00:00.1234567+02:00" ClientDoneResponse="2026-09-17T10:00:00.2345678+02:00" /></Session>"#;
    let loaded = saz::read(
        Cursor::new(minimal(Some(("raw/1_m.xml", xml)))),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(loaded.sessions[0].duration_ms, Some(111));
    let encoded = encode(&loaded.sessions, ExportMode::Full);
    let roundtrip = saz::read(Cursor::new(encoded), Limits::default()).unwrap();
    assert_eq!(
        roundtrip.sessions[0].archive.as_ref().unwrap().timers["ClientDoneResponse"],
        "2026-09-17T10:00:00.2345678+02:00"
    );
    assert_eq!(
        roundtrip.sessions[0].started_at,
        loaded.sessions[0].started_at
    );
}

#[test]
fn missing_responses_are_archived_as_incomplete_without_fabricating_a_status() {
    let bytes = archive(&[(
        "raw/42_c.txt",
        b"GET https://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n",
    )]);
    let loaded = saz::read(Cursor::new(bytes), Limits::default()).unwrap();
    let session = &loaded.sessions[0];
    assert!(session.status.is_none());
    assert!(!session.capture_complete());
    assert!(session.is_settled());
    assert!(inspect::render(session, Side::Response, Inspector::Text).contains("session ended"));
}

#[test]
fn decodes_chunk_framing_and_keeps_trailers_and_original_headers() {
    let bytes = archive(&[
        ("raw/1_c.txt", b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n"),
        ("raw/1_s.txt", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: x-checksum\r\n\r\n5\r\nhello\r\n6;ext=yes\r\n\0world\r\n0\r\nx-checksum: done\r\n\r\n"),
    ]);
    let original = saz::read(Cursor::new(bytes), Limits::default())
        .unwrap()
        .sessions;
    assert_eq!(original[0].response.data, b"hello\0world");
    assert_eq!(original[0].response.total_bytes, 11);
    assert_eq!(original[0].response.trailers[0].value, "done");
    let roundtrip = saz::read(
        Cursor::new(encode(&original, ExportMode::Full)),
        Limits::default(),
    )
    .unwrap()
    .sessions;
    assert_eq!(roundtrip[0].response.data, original[0].response.data);
    assert_eq!(roundtrip[0].response_headers, original[0].response_headers);
    assert_eq!(
        roundtrip[0].response.trailers,
        original[0].response.trailers
    );
}

#[test]
fn incomplete_chunked_and_content_length_bodies_are_marked_partial() {
    for body in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\npart".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\npart".as_slice(),
    ] {
        let bytes = archive(&[
            (
                "raw/1_c.txt",
                b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n",
            ),
            ("raw/1_s.txt", body),
        ]);
        let loaded = saz::read(Cursor::new(bytes), Limits::default()).unwrap();
        assert_eq!(loaded.sessions[0].response.data, b"part");
        assert!(!loaded.sessions[0].response.complete);
        assert!(!loaded.sessions[0].capture_complete());
        assert!(!loaded.warnings.is_empty());
    }
}

#[test]
fn retention_limits_keep_totals_and_survive_export_import() {
    let limits = Limits {
        capture: CaptureLimits {
            sessions: 5,
            body_bytes: 4,
            total_body_bytes: 6,
        },
        ..Limits::default()
    };
    let loaded = saz::load(&fixture(), limits).unwrap();
    let total: usize = loaded
        .sessions
        .iter()
        .map(|s| s.request.data.len() + s.response.data.len())
        .sum();
    assert_eq!(total, 6);
    assert_eq!(loaded.sessions[0].response.data.len(), 4);
    assert_eq!(loaded.sessions[0].response.total_bytes, 39);
    assert!(loaded.sessions[0].response.truncated());
    let roundtrip = saz::read(
        Cursor::new(encode(&loaded.sessions, ExportMode::Full)),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(roundtrip.sessions[0].response.data.len(), 4);
    assert_eq!(roundtrip.sessions[0].response.total_bytes, 39);
    assert!(roundtrip.sessions[0].response.truncated());
}

#[test]
fn sanitized_saz_never_hides_credentials_in_preserved_headers_or_metadata() {
    let mut sessions = saz::load(&fixture(), Limits::default()).unwrap().sessions;
    sessions[0].url = "https://example.test/?token=private-query&safe=yes".into();
    sessions[0]
        .archive
        .as_mut()
        .unwrap()
        .flags
        .insert("ui-comments".into(), "private-metadata".into());
    sessions[0]
        .archive
        .as_mut()
        .unwrap()
        .timers
        .insert("UnrecognizedSecret".into(), "private-timer".into());
    let encoded = encode(&sessions, ExportMode::Sanitized);
    let mut zip = ZipArchive::new(Cursor::new(&encoded)).unwrap();
    use std::io::Read;
    for i in 0..zip.len() {
        let mut bytes = Vec::new();
        zip.by_index(i).unwrap().read_to_end(&mut bytes).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        for secret in [
            "DEMO-NOT-A-REAL-TOKEN",
            "private-query",
            "private-metadata",
            "not-a-real-cookie",
            "private-timer",
        ] {
            assert!(!text.contains(secret), "{secret}");
        }
    }
    let loaded = saz::read(Cursor::new(encoded), Limits::default()).unwrap();
    assert!(
        loaded
            .sessions
            .iter()
            .all(|s| s.request.data.is_empty() && s.response.data.is_empty())
    );
    assert_eq!(
        header(&loaded.sessions[0].request_headers, "Authorization"),
        Some("[REDACTED]")
    );
    assert!(loaded.sessions[0].url.contains("safe=yes"));
    assert!(!loaded.sessions[0].url.contains("private-query"));
}

#[test]
fn index_escapes_capture_data_and_import_never_uses_its_html() {
    let mut sessions = saz::load(&fixture(), Limits::default()).unwrap().sessions;
    sessions[0].url = "https://example.test/?x=<script>alert(1)</script>&q='\"".into();
    let encoded = encode(&sessions, ExportMode::Full);
    let mut zip = ZipArchive::new(Cursor::new(encoded)).unwrap();
    use std::io::Read;
    let mut index = String::new();
    zip.by_name("_index.htm")
        .unwrap()
        .read_to_string(&mut index)
        .unwrap();
    assert!(!index.contains("<script>"));
    assert!(index.contains("&lt;script&gt;"));
    assert!(index.contains("&apos;"));
    let imported = saz::read(
        Cursor::new(minimal(Some((
            "_index.htm",
            b"<script>throw new Error('never run')</script>",
        )))),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(imported.sessions[0].response.data, b"hello");
}

#[test]
fn exports_http2_as_interoperable_http1_messages_with_original_protocol_metadata() {
    let store = CaptureStore::default();
    let id = store.begin(
        &Method::GET,
        &"https://example.test/h2".parse().unwrap(),
        Version::HTTP_2,
        &HeaderMap::new(),
        "127.0.0.1:1234".parse().unwrap(),
    );
    store.response(id, 200, Version::HTTP_2, &HeaderMap::new());
    store.complete_body(id, Side::Request);
    store.append(id, Side::Response, b"h2 bytes");
    store.complete_body(id, Side::Response);
    let encoded = encode(&store.all_sessions(), ExportMode::Full);
    let mut zip = ZipArchive::new(Cursor::new(&encoded)).unwrap();
    use std::io::Read;
    let mut raw = String::new();
    zip.by_name("raw/0001_c.txt")
        .unwrap()
        .read_to_string(&mut raw)
        .unwrap();
    assert!(raw.starts_with("GET https://example.test/h2 HTTP/1.1\r\n"));
    let loaded = saz::read(Cursor::new(encoded), Limits::default()).unwrap();
    assert_eq!(loaded.sessions[0].protocol, "HTTP/2");
    assert_eq!(loaded.sessions[0].response_protocol, "HTTP/2");
    assert_eq!(loaded.sessions[0].response.data, b"h2 bytes");
}

#[test]
fn rejects_paths_duplicate_sessions_and_orphan_responses() {
    for name in [
        "../escape",
        "/absolute",
        "C:\\escape",
        "raw/../../escape",
        "raw\\..\\escape",
    ] {
        let bytes = minimal(Some((name, b"not extracted")));
        assert!(
            saz::read(Cursor::new(bytes), Limits::default()).is_err(),
            "{name}"
        );
    }
    for name in ["raw/01_c.txt", "RAW/1_C.TXT"] {
        let bytes = minimal(Some((name, b"GET / HTTP/1.1\r\n\r\n")));
        assert!(saz::read(Cursor::new(bytes), Limits::default()).is_err());
    }
    let orphan = archive(&[("raw/1_s.txt", b"HTTP/1.1 200 OK\r\n\r\n")]);
    assert!(saz::read(Cursor::new(orphan), Limits::default()).is_err());
}

#[test]
fn rejects_dtds_entities_deep_or_malformed_metadata() {
    let deep = format!("<Session>{}</Session>", "<x>".repeat(40));
    for xml in [
        "<!DOCTYPE Session [<!ENTITY x SYSTEM 'file:///not-read'>]><Session><SessionFlags><SessionFlag N='test' V='&x;'/></SessionFlags></Session>",
        "<Session><SessionFlags><SessionFlag N='test' V='&unknown;'/></SessionFlags></Session>",
        "<Session><SessionTimers></Broken></Session>",
        "<Session><SessionFlags><SessionFlag N='same' V='1'/><SessionFlag N='SAME' V='2'/></SessionFlags></Session>",
        "<Session",
        "<NotSession/>",
        "<Session>&unknown;</Session>",
        &deep,
    ] {
        assert!(
            saz::read(
                Cursor::new(minimal(Some(("raw/1_m.xml", xml.as_bytes())))),
                Limits::default()
            )
            .is_err(),
            "{xml}"
        );
    }
}

#[test]
fn limits_apply_to_container_entries_expansion_metadata_and_session_count() {
    let bytes = minimal(None);
    for limits in [
        Limits {
            archive_bytes: 30,
            ..Limits::default()
        },
        Limits {
            entries: 1,
            ..Limits::default()
        },
        Limits {
            entry_bytes: 20,
            ..Limits::default()
        },
        Limits {
            expanded_bytes: 40,
            ..Limits::default()
        },
    ] {
        assert!(saz::read(Cursor::new(&bytes), limits).is_err());
    }
    let limits = Limits {
        capture: CaptureLimits {
            sessions: 1,
            ..CaptureLimits::default()
        },
        ..Limits::default()
    };
    assert!(saz::load(&fixture(), limits).is_err());
}

#[test]
fn encrypted_zip_is_rejected_without_prompting_or_attempting_a_password() {
    let mut bytes = minimal(None);
    let central = bytes.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
    bytes[6] |= 1;
    bytes[central + 8] |= 1;
    let error = saz::read(Cursor::new(bytes), Limits::default())
        .unwrap_err()
        .to_string();
    assert!(error.contains("Password-protected"), "{error}");
}

#[test]
fn ignores_websocket_frames_but_preserves_the_handshake_with_an_explicit_warning() {
    let bytes = archive(&[
        ("raw/1_c.txt", b"GET https://example.test/ws HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\n\r\n"),
        ("raw/1_s.txt", b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"),
        ("raw/1_w.txt", b"Opaque synthetic frame log"),
    ]);
    let loaded = saz::read(Cursor::new(bytes), Limits::default()).unwrap();
    assert_eq!(loaded.sessions[0].kind, SessionKind::WebSocket);
    assert!(loaded.warnings.iter().any(|w| w.contains("WebSocket")));
}

#[test]
fn importing_is_transactional_and_does_not_reuse_live_session_ids() {
    let store = CaptureStore::default();
    let old = store
        .begin(
            &Method::GET,
            &"http://old.test/".parse().unwrap(),
            Version::HTTP_11,
            &HeaderMap::new(),
            "127.0.0.1:1".parse().unwrap(),
        )
        .unwrap();
    let loaded = saz::load(&fixture(), Limits::default()).unwrap();
    store.replace_from_archive(loaded.sessions).unwrap();
    assert!(store.get(old).is_none());
    assert!(store.all_sessions()[0].id > old);
    store.append(Some(old), Side::Response, b"late traffic");
    assert_eq!(
        store.all_sessions()[0].response.data,
        br#"{"producer":"Fiddler","synthetic":true}"#
    );
    let mut invalid = store.all_sessions();
    invalid[0].response.total_bytes = 0;
    assert!(store.replace_from_archive(invalid).is_err());
    assert_eq!(store.all_sessions().len(), 3);
}

#[test]
fn export_is_atomic_and_rejects_header_injection_without_replacing_previous_data() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("capture.saz");
    let mut sessions = saz::load(&fixture(), Limits::default()).unwrap().sessions;
    std::fs::write(&path, b"previous").unwrap();
    sessions[0].request_headers.push(Header {
        name: "x-test".into(),
        value: "bad\r\ninjected: yes".into(),
    });
    assert!(saz::export(&path, &sessions, ExportMode::Full).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"previous");
    sessions[0].request_headers.pop();
    saz::export(&path, &sessions, ExportMode::Full).unwrap();
    assert_eq!(
        saz::load(&path, Limits::default()).unwrap().sessions.len(),
        3
    );
}
