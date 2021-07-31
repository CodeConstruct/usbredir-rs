use std::error;
use std::fmt;

#[derive(Debug, Clone)]
pub enum Error {
    Failed,
    IO,
    Parse,
    DeviceRejected,
    DeviceLost,
    Cancelled,
    Invalid,
    Stalled,
    Timeout,
    Babbled,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Failed => write!(f, "Operation failed"),
            Error::IO => write!(f, "IO error"),
            Error::Parse => write!(f, "Parse error"),
            Error::DeviceRejected => write!(f, "Device rejected"),
            Error::DeviceLost => write!(f, "Device lost"),
            Error::Cancelled => write!(f, "Transfer cancelled"),
            Error::Invalid => write!(f, "Invalid packet"),
            Error::Stalled => write!(f, "Stalled"),
            Error::Timeout => write!(f, "Timeout"),
            Error::Babbled => write!(f, "The device has babbled"),
        }
    }
}

impl error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
