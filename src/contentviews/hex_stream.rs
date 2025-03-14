use crate::contentviews::{Prettify, PrettifyError, Reencode, ReencodeError};
use pretty_hex::{HexConfig, PrettyHex};
use std::num::ParseIntError;

pub struct HexStream;

impl Prettify for HexStream {
    fn name(&self) -> &'static str {
        "Hex Stream"
    }

    fn prettify(&self, data: Vec<u8>) -> Result<String, PrettifyError> {
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

impl Reencode for HexStream {
    fn reencode(&self, data: String) -> anyhow::Result<Vec<u8>, ReencodeError> {
        (0..data.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&data[i..i + 2], 16))
            .collect::<anyhow::Result<Vec<u8>, ParseIntError>>()
            .map_err(|e| ReencodeError::InvalidFormat(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hexstream_deserialize() {
        let data = b"foo".to_vec();
        let result = HexStream.prettify(data).unwrap();
        assert_eq!(result, "666f6f");
    }

    #[test]
    fn test_hexstream_deserialize_empty() {
        let data = vec![];
        let result = HexStream.prettify(data).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_hexstream_serialize() {
        let data = "666f6f".to_string();
        let result = HexStream.reencode(data).unwrap();
        assert_eq!(result, b"foo");
    }
}
