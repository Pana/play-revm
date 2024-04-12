use std::{convert::From, error::Error, fmt::Display};

#[derive(Debug)]
pub struct RevmError(String);

impl Display for RevmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for RevmError {}

impl From<String> for RevmError {
    fn from(s: String) -> Self {
        RevmError(s)
    }
}
