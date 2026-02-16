use std::fmt;
use std::io;

#[derive(Debug)]
pub(crate) enum Error {
    Usage(String),
    Runtime(String),
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(msg) | Self::Runtime(msg) => write!(f, "{msg}"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
