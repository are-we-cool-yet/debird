use std::{process::ExitStatusError, str::Utf8Error, sync::mpsc::RecvError};

use pelite::pattern::{ParsePatError, Pattern};

#[derive(thiserror::Error, Debug)]
#[error("{0}")]
pub struct ImportNotFound(pub String);

#[derive(thiserror::Error, Debug)]
#[error("{0}")]
pub struct DriverError(pub String);

impl From<String> for DriverError {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("error loading library: {0}")]
    LibLoading(#[from] libloading::Error),
    #[error("error hooking function: {0:?}")]
    MhStatus(minhook::MH_STATUS),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Error reading PDB: {0}")]
    PdbError(#[from] pdb::Error),
    #[error("Error receiving message from thread: {0}")]
    RecvError(#[from] RecvError),
    #[error("Unsupported driver: {0}")]
    UnsupportedDriver(#[from] DriverError),
    #[error("Error in PeLite: {0}")]
    PeLiteError(#[from] pelite::Error),
    #[error("Patch not found at address: {0:?}")]
    PatchNotFound(Pattern),
    #[error("Error while parsing patch pattern: {0}")]
    PatternParseError(#[from] ParsePatError),
    #[error("Import required for hooking not found: {0}")]
    HookImportNotFound(ImportNotFound),
    #[error("Error parsing string as UTF-8: {0}")]
    Utf8Error(#[from] Utf8Error),
    #[error("Error from child process: {0}")]
    ExitStatusError(#[from] ExitStatusError),
}

impl From<minhook::MH_STATUS> for Error {
    fn from(value: minhook::MH_STATUS) -> Self {
        Self::MhStatus(value)
    }
}

impl From<Pattern> for Error {
    fn from(value: Pattern) -> Self {
        Self::PatchNotFound(value)
    }
}

pub type Result<T> = core::result::Result<T, Error>;
