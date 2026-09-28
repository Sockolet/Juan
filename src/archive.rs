use std::{fs::File, io::Read, path::Path};

use anyhow::{Context, Result};

use crate::{
    capture::Session,
    har::{self, ExportMode},
    saz,
};

pub fn load(path: &Path, limits: saz::Limits) -> Result<saz::ImportedArchive> {
    let extension = path.extension().and_then(|s| s.to_str());
    let har = match extension {
        Some(ext) if ext.eq_ignore_ascii_case("har") => true,
        Some(ext) if ext.eq_ignore_ascii_case("saz") => false,
        _ => looks_like_json(path)?,
    };
    if har {
        crate::har_import::load(path, limits.capture)
    } else {
        // Preserve SAZ's bounded ZIP validation for renamed archives and All files.
        saz::load(path, limits)
    }
}

// Renamed HARs (for example .json) begin with an object; anything else is validated as SAZ.
fn looks_like_json(path: &Path) -> Result<bool> {
    let mut prefix = Vec::new();
    File::open(path)
        .with_context(|| format!("Open archive {}", path.display()))?
        .take(1024)
        .read_to_end(&mut prefix)
        .context("Read archive prefix")?;
    let text = prefix.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&prefix);
    Ok(text.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{'))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Har,
    Saz,
}

impl Format {
    pub fn from_path(path: &Path) -> Self {
        if path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("saz"))
        {
            Self::Saz
        } else {
            Self::Har
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Har => "HAR",
            Self::Saz => "SAZ",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Har => "har",
            Self::Saz => "saz",
        }
    }

    pub fn export(self, path: &Path, sessions: &[Session], mode: ExportMode) -> Result<()> {
        match self {
            Self::Har => har::export(path, sessions, mode),
            Self::Saz => saz::export(path, sessions, mode),
        }
    }
}

pub(crate) fn atomic_write(path: &Path, write: impl FnOnce(&mut File) -> Result<()>) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent).context("Create archive output")?;
    write(temporary.as_file_mut())?;
    temporary
        .as_file()
        .sync_all()
        .context("Persist archive output")?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .context("Replace archive output file")?;
    Ok(())
}
