use std::{fmt::Display, str::FromStr};

use crate::error;

/// The target driver that we're dealing with
pub enum TargetDriver {
    CLIPSP
}

impl Display for TargetDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = f.write_str(match self {
            Self::CLIPSP => "clipsp.sys"
        }.to_uppercase().as_str());
        Ok(())
    }
}

impl FromStr for TargetDriver {
    type Err = error::DriverError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "clipsp.sys" => Ok(Self::CLIPSP),
            _ => Err(error::DriverError(s.to_string()))
        }
    }
}

