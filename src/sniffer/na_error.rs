use std::error::Error;
use std::fmt::{Display, Formatter};

/// The struct `NAError` defines custom error messages.
///
/// It contains a message of type [String] that includes a brief description of the error occurred, depending on the function
/// that calls it.
///
/// It implements Display and Error traits.
/// The list of possible errors raised is:
///
/// - in network_analyzer::sniffer:get_adapter()
///   - ⚠ **Device not found**
/// - in network_analyzer::sniffer:new()
///   - ⚠ **`Cap` Errors**
/// - in network_analyzer::sniffer::filter:get_filter()
///    - ⚠ **Not a valid IPv4 addr. as filter**
///    - ⚠ **Not an IP addr. as filter**
///    - ⚠ **Not a valid IPv6 addr. as filter**
///    - ⚠ **Not a valid packet length**
///    - ⚠ **Unavailable filter**
#[derive(Debug, Clone)]
pub struct NAError {
    message: String,
}

impl NAError {
    /// Creates a new `NAError` object starting from a [&str] msg received as parameter.
    pub fn new(msg: &str) -> Self { NAError { message: msg.to_string() } }
}

impl Display for NAError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "NAError: {}", self.message)
    }
}

impl Error for NAError {}
