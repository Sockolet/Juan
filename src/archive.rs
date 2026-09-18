use std::{fs::File, path::Path};

use anyhow::{Context, Result};

use crate::{
    capture::Session,
    har::{self, ExportMode},
    saz,
};

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
