//! Per-user archive path history. Never stores or reads archive contents.
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path, PathBuf, Prefix},
};

use anyhow::{Context, Result, ensure};
use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;

const MAX_FILES: usize = 5;
const MAX_BYTES: u64 = 1024 * 1024;

pub struct RecentFiles {
    file: PathBuf,
    paths: Vec<PathBuf>,
}

impl RecentFiles {
    pub fn empty(directory: &Path) -> Self {
        Self {
            file: directory.join("recent-files.json"),
            paths: Vec::new(),
        }
    }

    pub fn load(directory: &Path) -> Result<Self> {
        let mut history = Self::empty(directory);
        let input = match File::open(&history.file) {
            Ok(input) => input,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(history),
            Err(error) => return Err(error).context("Read recent-file history"),
        };
        let mut bytes = Vec::new();
        input.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "Recent-file history is too large"
        );
        let paths: Vec<PathBuf> =
            serde_json::from_slice(&bytes).context("Parse recent-file history")?;
        ensure!(
            paths.len() <= MAX_FILES,
            "Recent-file history exceeds five entries"
        );
        for path in paths {
            validate_local(&path)?;
            if !history.paths.iter().any(|p| same_path(p, &path)) {
                history.paths.push(path);
            }
        }
        Ok(history)
    }

    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// Call only after parsing and transactional session replacement both succeed.
    pub fn record_success(&mut self, path: &Path) -> Result<()> {
        let path = local_archive_path(path)?;
        let mut next = vec![path.clone()];
        next.extend(
            self.paths
                .iter()
                .filter(|p| !same_path(p, &path))
                .take(MAX_FILES - 1)
                .cloned(),
        );
        self.persist(&next)?;
        self.paths = next;
        Ok(())
    }

    pub fn clear(&mut self) -> Result<()> {
        self.persist(&[])?;
        self.paths.clear();
        Ok(())
    }

    fn persist(&self, paths: &[PathBuf]) -> Result<()> {
        let parent = self
            .file
            .parent()
            .context("Recent-file history has no parent")?;
        fs::create_dir_all(parent).context("Create recent-file history directory")?;
        let mut output =
            tempfile::NamedTempFile::new_in(parent).context("Create atomic recent-file update")?;
        serde_json::to_writer(&mut output, paths).context("Serialize recent-file paths")?;
        output.flush()?;
        output
            .as_file()
            .sync_all()
            .context("Flush recent-file history")?;
        output
            .persist(&self.file)
            .map_err(|e| e.error)
            .context("Replace recent-file history atomically")?;
        Ok(())
    }
}

pub fn local_archive_path(path: &Path) -> Result<PathBuf> {
    // Resolve symlinks before checking the local-drive boundary. No file contents are read.
    let path = fs::canonicalize(path).context("Locate recent archive")?;
    validate_local(&path)?;
    Ok(path)
}

fn validate_local(path: &Path) -> Result<()> {
    let drive = match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => Some(drive),
            _ => None,
        },
        _ => None,
    };
    ensure!(
        path.is_absolute() && drive.is_some(),
        "Recent files accepts only absolute local-drive paths, not network or device paths"
    );
    let root = super::system::wide(&format!("{}:\\", drive.unwrap() as char));
    // SAFETY: root is a terminated drive-root string and remains live for this call.
    let kind = unsafe { GetDriveTypeW(root.as_ptr()) };
    ensure!(
        // GetDriveType: absent removable root, removable, fixed, CD-ROM, RAM disk.
        // Retain offline local-drive history, but never mapped network drives (4).
        matches!(kind, 1 | 2 | 3 | 5 | 6),
        "Recent files accepts only local drives"
    );
    ensure!(
        path.extension()
            .and_then(|p| p.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("har") || s.eq_ignore_ascii_case("saz")),
        "Recent files accepts only HAR or SAZ paths"
    );
    ensure!(
        path.to_str().is_some(),
        "Recent-file path is not valid Unicode"
    );
    Ok(())
}

fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_lowercase()
        == b.to_string_lossy()
            .trim_start_matches(r"\\?\")
            .to_lowercase()
}

pub fn menu_label(path: &Path, index: usize) -> String {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let full = path.to_string_lossy();
    let label = format!("{name} ({})", full.trim_start_matches(r"\\?\"));
    format!(
        "&{} {}",
        index + 1,
        label.replace('&', "&&").replace(['\r', '\n', '\t'], " ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newest_five_deduplicate_and_roundtrip_without_contents() {
        let dir = tempfile::tempdir().unwrap();
        let mut history = RecentFiles::empty(dir.path());
        for i in 0..7 {
            let path = dir.path().join(format!("{i}.har"));
            fs::write(&path, "PRIVATE_SYNTHETIC_CONTENT").unwrap();
            history.record_success(&path).unwrap();
        }
        history.record_success(&dir.path().join("3.har")).unwrap();
        let loaded = RecentFiles::load(dir.path()).unwrap();
        let names: Vec<_> = loaded
            .paths()
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, ["3.har", "6.har", "5.har", "4.har", "2.har"]);
        assert!(
            !fs::read_to_string(&history.file)
                .unwrap()
                .contains("PRIVATE_SYNTHETIC_CONTENT")
        );
        history.clear().unwrap();
        assert!(RecentFiles::load(dir.path()).unwrap().paths().is_empty());
    }

    #[test]
    fn corrupt_and_failed_persistence_are_visible_and_keep_memory() {
        let dir = tempfile::tempdir().unwrap();
        let mut history = RecentFiles::empty(dir.path());
        let path = dir.path().join("one.saz");
        fs::write(&path, "").unwrap();
        history.record_success(&path).unwrap();
        fs::write(&history.file, "{broken").unwrap();
        assert!(RecentFiles::load(dir.path()).is_err());
        fs::remove_file(&history.file).unwrap();
        fs::create_dir(&history.file).unwrap();
        let before = history.paths().to_vec();
        assert!(history.clear().is_err());
        assert_eq!(history.paths(), before);
        assert!(history.record_success(&path).is_err());
        assert_eq!(history.paths(), before);
    }

    #[test]
    fn denied_atomic_replace_preserves_previous_disk_and_memory() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mut history = RecentFiles::empty(dir.path());
        let path = dir.path().join("one.har");
        fs::write(&path, "{}").unwrap();
        history.record_success(&path).unwrap();
        let before = fs::read(&history.file).unwrap();
        let held = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&history.file)
            .unwrap();
        assert!(history.clear().is_err());
        assert_eq!(history.paths().len(), 1);
        drop(held);
        assert_eq!(fs::read(&history.file).unwrap(), before);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn failed_archive_load_does_not_replace_prior_sessions_or_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capture.har");
        fs::write(&path, include_bytes!("../../tests/fixtures/har/chrome.har")).unwrap();
        let store = crate::capture::CaptureStore::default();
        let archive = crate::archive::load(&path, crate::saz::Limits::default()).unwrap();
        store.replace_from_archive(archive.sessions).unwrap();
        let mut history = RecentFiles::empty(dir.path());
        history.record_success(&path).unwrap();
        let before = store.snapshot().sessions[0].url.clone();
        fs::remove_file(&path).unwrap();
        assert!(crate::archive::load(&path, crate::saz::Limits::default()).is_err());
        assert_eq!(store.snapshot().sessions[0].url, before);
        assert_eq!(history.paths().len(), 1);
    }

    #[test]
    fn local_paths_only_missing_preserved_labels_disambiguate_and_escape() {
        for path in [
            r"\\server\share\one.har",
            r"\\?\UNC\server\share\one.har",
            r"\\.\C:\one.har",
            r"C:one.har",
            "https://example.test/one.har",
        ] {
            assert!(validate_local(Path::new(path)).is_err());
        }
        assert!(same_path(
            Path::new(r"C:\A.HAR"),
            Path::new(r"\\?\c:\a.har")
        ));
        assert_ne!(
            menu_label(Path::new(r"C:\a\one.har"), 0),
            menu_label(Path::new(r"C:\b\one.har"), 0)
        );
        assert!(menu_label(Path::new(r"C:\a&b\one.har"), 0).contains("a&&b"));
        let dir = tempfile::tempdir().unwrap();
        let mut history = RecentFiles::empty(dir.path());
        let path = dir.path().join("missing.har");
        fs::write(&path, "{}").unwrap();
        history.record_success(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(RecentFiles::load(dir.path()).unwrap().paths().len(), 1);
        assert!(local_archive_path(&path).is_err());
    }
}
