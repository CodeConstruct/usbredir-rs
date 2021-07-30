use std::fmt;
use std::error;

#[derive(Debug, Clone)]
pub enum Error {
    Failed,
    ReadIO,
    WriteIO,
    ReadParse,
    InvalidParameters,
    DeniedByRule,
    NoMatchingRule,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Failed => write!(f, "Operation failed"),
            Error::ReadIO => write!(f, "Read IO error"),
            Error::WriteIO => write!(f, "Write IO error"),
            Error::ReadParse => write!(f, "Read parsing error"),
            Error::InvalidParameters => write!(f, "Invalid parameters"),
            Error::DeniedByRule => write!(f, "Redirection is blocked by the filter rules"),
            Error::NoMatchingRule => write!(f, "None of the rules matched the device"),
        }
    }
}

impl error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
