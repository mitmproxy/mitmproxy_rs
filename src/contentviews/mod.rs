use anyhow::Result;
use pretty_hex::{HexConfig, PrettyHex};
use std::num::ParseIntError;

#[derive(Debug)]
pub enum SerializeError {
    InvalidFormat(String),
}

pub trait Contentview: Send + Sync {
    fn name(&self) -> &str;
    fn deserialize(&self, data: Vec<u8>) -> Result<String>;
}

pub trait SerializableContentview: Contentview {
    fn serialize(&self, data: String) -> Result<Vec<u8>, SerializeError>;
}

#[derive(Default)]
pub struct HexStream();

impl Contentview for HexStream {
    fn name(&self) -> &str {
        "HexStream"
    }

    fn deserialize(&self, data: Vec<u8>) -> Result<String> {
        Ok(data
            .hex_conf(HexConfig {
                title: false,
                ascii: false,
                width: 0,
                group: 0,
                chunk: 0,
                max_bytes: usize::MAX,
                display_offset: 0,
            })
            .to_string())
    }
}

impl SerializableContentview for HexStream {
    fn serialize(&self, data: String) -> Result<Vec<u8>, SerializeError> {
        (0..data.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&data[i..i + 2], 16))
            .collect::<Result<Vec<u8>, ParseIntError>>()
            .map_err(|e| {
                SerializeError::InvalidFormat(format!("Failed to parse hex string: {}", e))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hexstream_deserialize() {
        let hex_stream = HexStream::default();
        let data = b"foo".to_vec();
        let result = hex_stream.deserialize(data).unwrap();
        assert_eq!(result, "666f6f");
    }

    #[test]
    fn test_hexstream_deserialize_empty() {
        let hex_stream = HexStream::default();
        let data = vec![];
        let result = hex_stream.deserialize(data).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_hexstream_serialize() {
        let hex_stream = HexStream::default();
        let data = "666f6f".to_string();
        let result = hex_stream.serialize(data).unwrap();
        assert_eq!(result, b"foo");
    }
}
