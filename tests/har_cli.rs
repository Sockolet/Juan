use serde_json::Value;
use std::{path::PathBuf, process::Command};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("har")
        .join(name)
}
fn directory() -> tempfile::TempDir {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("har-tests");
    std::fs::create_dir_all(&root).unwrap();
    tempfile::tempdir_in(root).unwrap()
}
fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_juan-cli"))
}

#[test]
fn har_cli_is_offline_and_reports_source_sizes_and_fractional_timings() {
    let profile = directory();
    for name in ["Juan", "Widdler"] {
        let data = profile.path().join(name);
        std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("proxy-restore.dpapi"), b"do not read or change").unwrap();
    }
    for name in ["chrome.har", "edge.har", "firefox.har"] {
        let result = cli()
            .env("LOCALAPPDATA", profile.path())
            .arg("inspect")
            .arg(fixture(name))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let row: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(row["har"]["source"], "HAR");
        if name == "chrome.har" {
            assert_eq!(row["elapsedMs"], 12.875);
            assert_eq!(row["har"]["response"]["wire_size"], 9);
            assert_eq!(row["bytes"], 17);
        }
        if name == "firefox.har" {
            assert_eq!(row["proxyError"], false);
            assert_eq!(row["sourceError"], true);
        }
    }
    for name in ["Juan", "Widdler"] {
        let data = profile.path().join(name);
        assert_eq!(
            std::fs::read(data.join("proxy-restore.dpapi")).unwrap(),
            b"do not read or change"
        );
        assert!(!data.join("root-ca.dpapi").exists());
    }
}

#[test]
fn full_and_safe_exports_work_and_saz_failure_preserves_existing_destination() {
    let dir = directory();
    for full in [false, true] {
        let output = dir.path().join(if full { "full.har" } else { "safe.har" });
        let mut command = cli();
        command
            .arg("inspect")
            .arg(fixture("chrome.har"))
            .arg("--export")
            .arg(&output);
        if full {
            command.arg("--full");
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let text = std::fs::read_to_string(&output).unwrap();
        assert_eq!(text.contains("private-body"), full);
        assert!(cli().arg("inspect").arg(output).status().unwrap().success());
    }
    let output = dir.path().join("existing.saz");
    std::fs::write(&output, b"preserve destination").unwrap();
    let result = cli()
        .arg("inspect")
        .arg(fixture("chrome.har"))
        .arg("--export")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("HAR-to-SAZ"));
    assert_eq!(std::fs::read(&output).unwrap(), b"preserve destination");
    let invalid = dir.path().join("invalid.har");
    std::fs::write(&invalid, b"{bad").unwrap();
    assert!(
        !cli()
            .arg("inspect")
            .arg(invalid)
            .arg("--export")
            .arg(&output)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(std::fs::read(output).unwrap(), b"preserve destination");
}
