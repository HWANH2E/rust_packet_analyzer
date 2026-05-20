use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum AnalyzerError {
    Io(std::io::Error),
    InvalidFormat(String),
    Unsupported(String),
    Truncated {
        context: &'static str,
        needed: usize,
        available: usize,
    },
    InvalidArgument(String),
}

impl AnalyzerError {
    pub fn truncated(context: &'static str, needed: usize, available: usize) -> Self {
        Self::Truncated {
            context,
            needed,
            available,
        }
    }
}

impl Display for AnalyzerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::InvalidFormat(message) => write!(f, "invalid format: {message}"),
            Self::Unsupported(message) => write!(f, "unsupported: {message}"),
            Self::Truncated {
                context,
                needed,
                available,
            } => write!(
                f,
                "truncated {context}: needed {needed} bytes, available {available} bytes"
            ),
            Self::InvalidArgument(message) => write!(f, "invalid argument: {message}"),
        }
    }
}

impl std::error::Error for AnalyzerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for AnalyzerError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, AnalyzerError>;
