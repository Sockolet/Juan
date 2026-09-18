use std::{path::PathBuf, process::Command};

use juan::{har::ExportMode, saz};
use serde_json::Value;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("fiddler-reference.saz")
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_juan-cli"))
}

#[test]
fn offline_inspection_does_not_touch_proxy_recovery_or_certificate_state() {
    let profile = tempfile::tempdir().unwrap();
    let data = profile.path().join("Juan");
    std::fs::create_dir(&data).unwrap();
    let recovery = data.join("proxy-restore.dpapi");
    std::fs::write(
        &recovery,
        b"not a DPAPI blob - offline inspection must never read this",
    )
    .unwrap();
    let legacy = profile.path().join("Widdler");
    std::fs::create_dir(&legacy).unwrap();
    std::fs::write(
        legacy.join("proxy-restore.dpapi"),
        b"legacy recovery must stay untouched",
    )
    .unwrap();
    let result = cli()
        .env("LOCALAPPDATA", profile.path())
        .arg("inspect")
        .arg(fixture())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8(result.stdout).unwrap();
    let rows: Vec<Value> = output
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["status"], 200);
    assert_eq!(rows[1]["method"], "POST");
    assert_eq!(rows[0]["elapsedMs"], 25);
    assert_eq!(
        std::fs::read(recovery).unwrap(),
        b"not a DPAPI blob - offline inspection must never read this"
    );
    assert!(!data.join("root-ca.dpapi").exists());
    assert_eq!(
        std::fs::read(legacy.join("proxy-restore.dpapi")).unwrap(),
        b"legacy recovery must stay untouched"
    );
}

#[test]
fn cli_converts_saz_to_har_and_saz_with_explicit_sensitive_export() {
    let directory = tempfile::tempdir().unwrap();
    let har = directory.path().join("capture.har");
    let result = cli()
        .arg("inspect")
        .arg(fixture())
        .arg("--export")
        .arg(&har)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&std::fs::read(har).unwrap()).unwrap();
    assert_eq!(value["log"]["entries"].as_array().unwrap().len(), 3);
    assert_eq!(
        value["log"]["entries"][0]["response"]["content"]["_bodyOmitted"],
        true
    );
    let output = directory.path().join("capture.saz");
    let result = cli()
        .arg("inspect")
        .arg(fixture())
        .arg("--export")
        .arg(&output)
        .arg("--full")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let imported = saz::load(&output, saz::Limits::default()).unwrap();
    assert_eq!(
        imported.sessions[1].request.data,
        [0, 1, 255, 13, 10, 83, 65, 90]
    );
    let sanitized = directory.path().join("sanitized.saz");
    let result = cli()
        .arg("inspect")
        .arg(fixture())
        .arg("--export")
        .arg(&sanitized)
        .output()
        .unwrap();
    assert!(result.status.success());
    let imported = saz::load(&sanitized, saz::Limits::default()).unwrap();
    assert!(
        imported
            .sessions
            .iter()
            .all(|session| session.request.data.is_empty() && session.response.data.is_empty())
    );
}

#[test]
fn invalid_archive_or_arguments_fail_without_overwriting_output() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("invalid.saz");
    let output = directory.path().join("existing.saz");
    std::fs::write(&input, b"not a ZIP").unwrap();
    std::fs::write(&output, b"keep this file").unwrap();
    let result = cli()
        .arg("inspect")
        .arg(&input)
        .arg("--export")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(std::fs::read(output).unwrap(), b"keep this file");
    assert!(
        !cli()
            .args(["inspect", "--full"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !cli()
            .arg("inspect")
            .arg(fixture())
            .arg("--unknown")
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn missing_har_timing_is_reported_instead_of_fabricated() {
    let directory = tempfile::tempdir().unwrap();
    let original = saz::load(&fixture(), saz::Limits::default()).unwrap();
    let mut sessions = original.sessions;
    sessions[0].started_at = None;
    sessions[0].duration_ms = None;
    sessions[0].archive.as_mut().unwrap().timers.clear();
    let input = directory.path().join("unknown-times.saz");
    saz::export(&input, &sessions, ExportMode::Full).unwrap();
    let result = cli()
        .arg("inspect")
        .arg(&input)
        .arg("--export")
        .arg(directory.path().join("output.har"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("no recorded"));
    assert!(!directory.path().join("output.har").exists());
}
