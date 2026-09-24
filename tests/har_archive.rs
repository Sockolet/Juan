use juan::{
    capture::{CaptureLimits, CaptureStore, Side},
    har::{self, ExportMode},
    har_import::{self, INPUT_LIMIT, Representation},
    inspect::{self, Inspector},
};
use serde_json::{Value, json};
use std::io::{Cursor, Read};

const CHROME: &[u8] = include_bytes!("fixtures/har/chrome.har");
const EDGE: &[u8] = include_bytes!("fixtures/har/edge.har");
const FIREFOX: &[u8] = include_bytes!("fixtures/har/firefox.har");
fn sample() -> Value {
    serde_json::from_slice(CHROME).unwrap()
}
fn parse(value: &Value) -> juan::saz::ImportedArchive {
    har_import::read(
        serde_json::to_vec(value).unwrap().as_slice(),
        CaptureLimits::default(),
    )
    .unwrap()
}
fn roundtrip(session: juan::capture::Session, mode: ExportMode) -> (Value, juan::capture::Session) {
    let mut bytes = Vec::new();
    har::write_har(&mut bytes, &[session], mode).unwrap();
    let json = serde_json::from_slice(&bytes).unwrap();
    let session = har_import::read(bytes.as_slice(), CaptureLimits::default())
        .unwrap()
        .sessions
        .remove(0);
    (json, session)
}

#[test]
fn browser_fixtures_preserve_decoded_content_duplicates_and_fractional_timing() {
    for bytes in [CHROME, EDGE, FIREFOX] {
        let imported = har_import::read(bytes, CaptureLimits::default()).unwrap();
        assert_eq!(imported.sessions.len(), 1);
        let store = CaptureStore::default();
        store.replace_from_archive(imported.sessions).unwrap();
        let session = store.all_sessions().remove(0);
        let evidence = session.archive.as_ref().unwrap().har.as_ref().unwrap();
        assert!(session.is_settled());
        assert!(session.client.is_empty());
        if evidence.creator.name == "Chrome" {
            assert_eq!(
                inspect::decode_body(&session, Side::Response, 1024).unwrap(),
                b"already decoded!!"
            );
            assert_eq!(session.request_headers[0].value, "one");
            assert_eq!(session.request_headers[1].value, "two");
            assert!(session.url.ends_with("&x=1&x=2"));
            assert_eq!(evidence.time, 12.875);
            assert_eq!(evidence.timings["wait"], 11.25);
            assert_eq!(evidence.response.wire_size, 9);
            assert_eq!(session.response.total_bytes, 17);
            assert_eq!(session.summary().content_type, "text/plain");
            assert!(
                inspect::render(&session, Side::Response, Inspector::Headers)
                    .contains("Recorded reason")
            );
            assert!(inspect::render_timing(&session).contains("12.875"));
        } else if evidence.creator.name == "Microsoft Edge" {
            assert_eq!(session.response.data, [0, 255, 1]);
            assert_eq!(session.elapsed_ms(), None);
        } else {
            assert_eq!(session.status, None);
            assert_eq!(session.error.as_deref(), Some("NS_ERROR_FAILURE"));
        }
        let (_, again) = roundtrip(session.clone(), ExportMode::Full);
        assert_eq!(again.response.data, session.response.data);
        assert_eq!(again.url, session.url);
        assert_eq!(
            again
                .archive
                .as_ref()
                .unwrap()
                .har
                .as_ref()
                .unwrap()
                .creator
                .name,
            evidence.creator.name
        );
        assert_eq!(
            again
                .archive
                .as_ref()
                .unwrap()
                .har
                .as_ref()
                .unwrap()
                .server_ip,
            evidence.server_ip
        );
    }
}

#[test]
fn params_remain_structured_and_sanitized_export_contains_no_body_secrets() {
    let session = parse(&sample()).sessions.remove(0);
    assert!(session.request.data.is_empty());
    let text = inspect::render(&session, Side::Request, Inspector::Text);
    assert!(text.contains("Structured form parameters"));
    let (full, _) = roundtrip(session.clone(), ExportMode::Full);
    assert!(
        full["log"]["entries"][0]["request"]["postData"]
            .get("text")
            .is_none()
    );
    assert_eq!(
        full["log"]["entries"][0]["request"]["postData"]["params"][1]["fileName"],
        "secret.txt"
    );
    let (safe, again) = roundtrip(session, ExportMode::Sanitized);
    let safe_text = safe.to_string();
    for secret in [
        "private-token",
        "private-auth",
        "private-body",
        "private-cookie",
        "secret.txt",
        "already decoded",
    ] {
        assert!(!safe_text.contains(secret), "{secret}");
    }
    assert!(again.response.data.is_empty());
    assert_eq!(
        again.archive.unwrap().har.unwrap().response.availability,
        "omitted by source"
    );
}

#[test]
fn distinguishes_absent_empty_omitted_partial_invalid_and_unknown_encoding() {
    for (content, expected, warning) in [
        (json!({"size":0}), "absent from export", false),
        (json!({"size":0,"text":""}), "present", false),
        (
            json!({"text":"secret","_bodyOmitted":true}),
            "omitted by source",
            false,
        ),
        (
            json!({"text":"prefix","_partial":true}),
            "partial in source",
            false,
        ),
        (
            json!({"text":"bad!","encoding":"base64"}),
            "invalid or unsupported body encoding",
            true,
        ),
        (
            json!({"text":"abc","encoding":"vendor"}),
            "invalid or unsupported body encoding",
            true,
        ),
    ] {
        let mut value = sample();
        value["log"]["entries"][0]["response"]["content"] = content;
        let mut imported = parse(&value);
        assert_eq!(!imported.warnings.is_empty(), warning);
        let session = imported.sessions.remove(0);
        assert_eq!(
            session
                .archive
                .as_ref()
                .unwrap()
                .har
                .as_ref()
                .unwrap()
                .response
                .availability,
            expected
        );
        let (_, again) = roundtrip(session, ExportMode::Full);
        assert_eq!(
            again.archive.unwrap().har.unwrap().response.availability,
            expected
        );
    }
}

#[test]
fn retention_counts_representation_not_compressed_wire_size_and_roundtrips_prefix() {
    let mut value = sample();
    value["log"]["entries"][0]["request"]["postData"] = json!({"text":"abcdef"});
    value["log"]["entries"][0]["response"]["content"] = json!({"text":"abcdefghij","size":10});
    value["log"]["entries"][0]["response"]["bodySize"] = json!(2);
    let limits = CaptureLimits {
        sessions: 1,
        body_bytes: 4,
        total_body_bytes: 6,
    };
    let bytes = serde_json::to_vec(&value).unwrap();
    let mut imported = har_import::read(bytes.as_slice(), limits).unwrap();
    let session = imported.sessions.remove(0);
    assert_eq!(session.request.data, b"abcd");
    assert_eq!(session.response.data, b"ab");
    assert_eq!(session.response.total_bytes, 10);
    assert_eq!(imported.warnings.len(), 2);
    let (_, again) = roundtrip(session, ExportMode::Full);
    assert_eq!(again.response.total_bytes, 10);
    assert!(again.response.truncated());
}

#[test]
fn malformed_essential_structure_or_any_entry_is_fatal_and_store_is_untouched() {
    let store = CaptureStore::default();
    store
        .replace_from_archive(parse(&sample()).sessions)
        .unwrap();
    let before = store.all_sessions()[0].id;
    for invalid in [
        json!({"log":{}}),
        {
            let mut v = sample();
            v["log"]["version"] = json!("1.1");
            v
        },
        {
            let mut v = sample();
            v["log"]["entries"][0]["request"]["method"] = json!("bad method");
            v
        },
        {
            let mut v = sample();
            v["log"]["entries"][0]["response"]["status"] = json!(999);
            v
        },
        {
            let mut v = sample();
            v["log"]["entries"][0]["startedDateTime"] = json!("bad");
            v
        },
        {
            let mut v = sample();
            v["log"]["entries"][0]["time"] = json!(-0.5);
            v
        },
        {
            let mut v = sample();
            v["log"]["entries"].as_array_mut().unwrap().push(json!({}));
            v
        },
    ] {
        let bytes = serde_json::to_vec(&invalid).unwrap();
        assert!(har_import::read(bytes.as_slice(), CaptureLimits::default()).is_err());
        assert_eq!(store.all_sessions()[0].id, before);
    }
}

#[test]
fn limits_1000_entries_are_inclusive_no_silent_skips() {
    let mut value = sample();
    let entry = value["log"]["entries"][0].clone();
    value["log"]["entries"] = json!(vec![entry.clone(); 1000]);
    assert_eq!(parse(&value).sessions.len(), 1000);
    value["log"]["entries"].as_array_mut().unwrap().push(entry);
    assert!(
        har_import::read(
            serde_json::to_vec(&value).unwrap().as_slice(),
            CaptureLimits::default()
        )
        .is_err()
    );
}

#[test]
fn input_boundary_is_exactly_128_mib_and_reader_does_not_trust_file_metadata() {
    assert_eq!(INPUT_LIMIT, 134217728);
    for extra in [0, 1] {
        let source = Cursor::new(CHROME)
            .chain(std::io::repeat(b' ').take(INPUT_LIMIT - CHROME.len() as u64 + extra));
        let result = har_import::read(source, CaptureLimits::default());
        assert_eq!(result.is_ok(), extra == 0, "{result:?}");
    }
}

#[test]
fn base64_prefix_validates_even_unretained_tail_and_preserves_binary_provenance() {
    let mut value = sample();
    value["log"]["entries"][0]["response"]["content"] =
        json!({"text":"YWJjZA==","encoding":"base64"});
    let session = parse(&value).sessions.remove(0);
    let (full, again) = roundtrip(session, ExportMode::Full);
    assert_eq!(
        full["log"]["entries"][0]["response"]["content"]["encoding"],
        "base64"
    );
    assert_eq!(
        again.archive.unwrap().har.unwrap().response.representation,
        Representation::DecodedBinary
    );
    value["log"]["entries"][0]["response"]["content"]["text"] = json!("YWJjZA==!");
    let bytes = serde_json::to_vec(&value).unwrap();
    let result = har_import::read(
        bytes.as_slice(),
        CaptureLimits {
            sessions: 1,
            body_bytes: 1,
            total_body_bytes: 1,
        },
    )
    .unwrap();
    assert!(result.sessions[0].response.data.is_empty());
    assert!(!result.warnings.is_empty());
}

#[test]
fn har_origin_saz_export_refused_for_both_modes() {
    let sessions = parse(&sample()).sessions;
    for mode in [ExportMode::Sanitized, ExportMode::Full] {
        let error = juan::saz::write(Cursor::new(Vec::new()), &sessions, mode).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("HAR-to-SAZ conversion is deferred")
        );
    }
}

#[test]
fn reads_juan_export_and_does_not_double_decode_gzip() {
    let store = CaptureStore::default();
    let id = store.begin(
        &http::Method::GET,
        &"https://example.test/".parse().unwrap(),
        http::Version::HTTP_11,
        &http::HeaderMap::new(),
        "127.0.0.1:1".parse().unwrap(),
    );
    let mut headers = http::HeaderMap::new();
    headers.insert("content-encoding", "gzip".parse().unwrap());
    store.response(id, 200, http::Version::HTTP_11, &headers);
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, b"decoded").unwrap();
    store.append(id, Side::Response, &encoder.finish().unwrap());
    store.complete_body(id, Side::Response);
    let session = store.get(id.unwrap()).unwrap();
    let (_, imported) = roundtrip(session, ExportMode::Full);
    assert_eq!(
        inspect::decode_body(&imported, Side::Response, 1024).unwrap(),
        b"decoded"
    );
}

#[test]
fn actual_default_body_and_aggregate_limits_are_inclusive() {
    let mut value = sample();
    value["log"]["entries"][0]["response"]["content"] =
        json!({"text": "x".repeat(1024 * 1024 + 1), "size": 1024 * 1024 + 1});
    let entry = value["log"]["entries"][0].clone();
    value["log"]["entries"] = json!(vec![entry; 65]);
    let imported = parse(&value);
    assert_eq!(
        imported
            .sessions
            .iter()
            .map(|s| s.response.data.len())
            .sum::<usize>(),
        64 * 1024 * 1024
    );
    assert_eq!(imported.sessions[63].response.data.len(), 1024 * 1024);
    assert!(imported.sessions[64].response.data.is_empty());
    assert_eq!(imported.sessions[64].response.total_bytes, 1024 * 1024 + 1);
}

#[test]
fn wire_fallback_is_decoded_once_and_invalid_optional_forms_warn() {
    use base64::Engine as _;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, b"wire fallback").unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode(encoder.finish().unwrap());
    let mut value = sample();
    value["log"]["entries"][0]["response"]["content"] = json!({"_wireBodyBase64": encoded});
    value["log"]["entries"][0]["request"]["postData"] = json!({"params": "invalid"});
    let mut imported = parse(&value);
    assert_eq!(imported.warnings.len(), 1);
    let session = imported.sessions.remove(0);
    assert_eq!(
        inspect::decode_body(&session, Side::Response, 1024).unwrap(),
        b"wire fallback"
    );
    let (_, again) = roundtrip(session, ExportMode::Full);
    assert_eq!(
        inspect::decode_body(&again, Side::Response, 1024).unwrap(),
        b"wire fallback"
    );
}

#[test]
fn unknown_vendor_timing_trees_are_ignored_and_juan_errors_keep_source_origin() {
    let mut value = sample();
    value["log"]["entries"][0]["timings"]["_vendor"] = json!({"tree":[1,2,3]});
    value["log"]["entries"][0]["_juan"] = json!({"error":"source proxy failure"});
    let session = parse(&value).sessions.remove(0);
    assert_eq!(session.error.as_deref(), Some("source proxy failure"));
    assert!(
        !session
            .archive
            .as_ref()
            .unwrap()
            .har
            .as_ref()
            .unwrap()
            .timings
            .contains_key("_vendor")
    );
    assert!(
        inspect::render(&session, Side::Response, Inspector::Headers)
            .contains("HAR source diagnostic")
    );
}

#[test]
fn utf8_retention_prefix_roundtrips_with_original_text_representation() {
    let mut value = sample();
    value["log"]["entries"][0]["response"]["content"] = json!({"text":"é"});
    let bytes = serde_json::to_vec(&value).unwrap();
    let mut imported = har_import::read(
        bytes.as_slice(),
        CaptureLimits {
            sessions: 1,
            body_bytes: 1,
            total_body_bytes: 1,
        },
    )
    .unwrap();
    let (_, again) = roundtrip(imported.sessions.remove(0), ExportMode::Full);
    assert_eq!(again.response.data, [0xc3]);
    assert_eq!(
        again.archive.unwrap().har.unwrap().response.representation,
        Representation::Text
    );
}

#[test]
fn original_url_userinfo_escapes_query_order_and_fragment_survive_full_export() {
    let mut value = sample();
    let url = "https://user:pass@example.test/a%2Fb?x=1&x=2#fragment";
    value["log"]["entries"][0]["request"]["url"] = json!(url);
    let session = parse(&value).sessions.remove(0);
    assert_eq!(session.url, url);
    let (_, again) = roundtrip(session.clone(), ExportMode::Full);
    assert_eq!(again.url, url);
    let (safe, _) = roundtrip(session, ExportMode::Sanitized);
    let safe_url = safe["log"]["entries"][0]["request"]["url"]
        .as_str()
        .unwrap();
    assert!(!safe_url.contains("user:pass") && !safe_url.contains("fragment"));
}

#[test]
fn root_provenance_is_shared_and_parameter_previews_are_bounded() {
    let mut value = sample();
    value["log"]["entries"][0]["request"]["postData"]["params"] =
        json!([{"name":"large","value":"x".repeat(3 * 1024 * 1024)}]);
    let entry = value["log"]["entries"][0].clone();
    value["log"]["entries"].as_array_mut().unwrap().push(entry);
    let imported = parse(&value);
    let first = imported.sessions[0]
        .archive
        .as_ref()
        .unwrap()
        .har
        .as_ref()
        .unwrap();
    let second = imported.sessions[1]
        .archive
        .as_ref()
        .unwrap()
        .har
        .as_ref()
        .unwrap();
    assert!(std::sync::Arc::ptr_eq(&first.creator, &second.creator));
    let text = inspect::render(&imported.sessions[0], Side::Request, Inspector::Text);
    assert!(text.len() < 4096);
    assert!(text.contains("exceeds the preview limit"));
}
