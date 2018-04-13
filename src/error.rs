use std::fmt;
use std::error::Error as StdError;

#[derive(Debug)]
pub struct CmdipassError {
    message: String,
}

impl CmdipassError {
    pub fn new<T: AsRef<str>>(input: T) -> CmdipassError {
        CmdipassError { message: String::from(input.as_ref()) }
    }
}

impl fmt::Display for CmdipassError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl StdError for CmdipassError {
    fn description(&self) -> &str {
        self.message.as_ref()
    }
}
