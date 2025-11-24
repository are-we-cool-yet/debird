use std::{fmt::Display, sync::mpsc::RecvError};

#[derive(thiserror::Error, Debug)]
pub struct DriverError(pub String);

impl From<String> for DriverError {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl Display for DriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)?;
        Ok(())
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
}

impl From<minhook::MH_STATUS> for Error {
    fn from(value: minhook::MH_STATUS) -> Self {
        Self::MhStatus(value)
    }
}

pub type Result<T> = core::result::Result<T, Error>;
