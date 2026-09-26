use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Timeout(&'static str),
    Hci { opcode: u16, status: u8 },
    NotFound(String),
    InvalidState(String),
    InvalidArgument(String),
    NotSupported(String),
    PairingFailed(String),
    ConnectionFailed(String),
    L2cap(String),
    Sdp(String),
    Att { code: u8, handle: u16 },
    Serialization(String),
    PermissionDenied(String),
    TransportClosed,
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Timeout(w) => write!(f, "timeout waiting for {w}"),
            Error::Hci { opcode, status } => write!(f, "hci command 0x{opcode:04x} failed: {status} ({})", hci_status_text(*status)),
            Error::NotFound(w) => write!(f, "not found: {w}"),
            Error::InvalidState(w) => write!(f, "invalid state: {w}"),
            Error::InvalidArgument(w) => write!(f, "invalid argument: {w}"),
            Error::NotSupported(w) => write!(f, "not supported: {w}"),
            Error::PairingFailed(w) => write!(f, "pairing failed: {w}"),
            Error::ConnectionFailed(w) => write!(f, "connection failed: {w}"),
            Error::L2cap(w) => write!(f, "l2cap: {w}"),
            Error::Sdp(w) => write!(f, "sdp: {w}"),
            Error::Att { code, handle } => write!(f, "att error 0x{code:02x} at handle 0x{handle:04x}"),
            Error::Serialization(w) => write!(f, "serialization: {w}"),
            Error::PermissionDenied(w) => write!(f, "permission denied: {w}"),
            Error::TransportClosed => write!(f, "hci transport closed"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error { fn from(e: std::io::Error) -> Self { Error::Io(e) } }
impl From<serde_json::Error> for Error { fn from(e: serde_json::Error) -> Self { Error::Serialization(e.to_string()) } }
impl From<std::sync::mpsc::RecvTimeoutError> for Error {
    fn from(_: std::sync::mpsc::RecvTimeoutError) -> Self { Error::Timeout("channel") }
}

pub fn hci_status_text(s: u8) -> &'static str {
    match s {
        0x00 => "success",
        0x01 => "unknown hci command",
        0x02 => "unknown connection identifier",
        0x03 => "hardware failure",
        0x04 => "page timeout",
        0x05 => "authentication failure",
        0x06 => "pin or key missing",
        0x07 => "memory capacity exceeded",
        0x08 => "connection timeout",
        0x09 => "connection limit exceeded",
        0x0A => "synchronous connection limit exceeded",
        0x0B => "acl connection already exists",
        0x0C => "command disallowed",
        0x11 => "unsupported feature or parameter",
        0x12 => "invalid hci command parameters",
        0x13 => "remote user terminated connection",
        0x14 => "remote low resources",
        0x15 => "remote power off",
        0x16 => "connection terminated by local host",
        0x17 => "repeated attempts",
        0x18 => "pairing not allowed",
        0x1A => "unsupported remote feature",
        0x22 => "lmp pdu not allowed",
        0x24 => "operation not allowed",
        0x34 => "host timeout",
        0x3F => "unspecified error",
        _ => "unknown status",
    }
}

pub fn att_status_text(c: u8) -> &'static str {
    match c {
        0x01 => "invalid handle",
        0x02 => "read not permitted",
        0x03 => "write not permitted",
        0x05 => "insufficient authentication",
        0x06 => "unsupported request",
        0x07 => "invalid offset",
        0x08 => "insufficient authorization",
        0x0A => "attribute not found",
        0x0B => "attribute not long",
        0x0D => "insufficient encryption key size",
        0x0E => "invalid attribute value length",
        0x0F => "insufficient encryption",
        0x11 => "insufficient resources",
        _ => "att error",
    }
}