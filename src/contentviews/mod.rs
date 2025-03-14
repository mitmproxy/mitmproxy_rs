mod hex_dump;
mod hex_stream;
mod msgpack;

use anyhow::Result;
use std::fmt::{Display, Formatter};

pub use hex_dump::HexDump;
pub use hex_stream::HexStream;
pub use msgpack::MsgPack;

#[derive(Debug)]
pub enum ReencodeError {
    InvalidFormat(String),
}

impl Display for ReencodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ReencodeError::InvalidFormat(e) => {
                write!(f, "invalid format: {}", e)
            }
        }
    }
}

#[derive(Debug)]
pub enum PrettifyError {
    Generic(String),
}

impl Display for PrettifyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PrettifyError::Generic(e) => {
                write!(f, "deserialize error: {}", e)
            }
        }
    }
}

pub trait Prettify: Send + Sync {
    fn name(&self) -> &str;

    fn instance_name(&self) -> String {
        self.name().to_lowercase().replace(" ", "_")
    }

    fn prettify(&self, data: Vec<u8>) -> Result<String, PrettifyError>;
}

pub trait Reencode: Send + Sync {
    fn reencode(&self, data: String) -> Result<Vec<u8>, ReencodeError>;
}
