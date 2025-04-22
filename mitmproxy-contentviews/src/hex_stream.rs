use crate::{Metadata, Prettify, Reencode};
use anyhow::{Context, Result};

pub struct HexStream;

pub(crate) fn is_binary(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let ratio = data
        .iter()
        .take(100)
        .filter(|&&b| b < 9 || (13 < b && b < 32) || b > 126)
        .count() as f64
        / data.len().min(100) as f64;

    ratio > 0.3
}

impl Prettify for HexStream {
    fn name(&self) -> &'static str {
        "Hex Stream"
    }

    fn prettify(&self, data: &[u8], _metadata: &dyn Metadata) -> Result<String> {
        Ok(data_encoding::HEXLOWER.encode(data))
    }

    fn render_priority(&self, data: &[u8], _metadata: &dyn Metadata) -> f32 {
        if is_binary(data) {
            0.4
        } else {
            0.0
        }
    }
}

impl Reencode for HexStream {
    fn reencode(&self, data: &str, _metadata: &dyn Metadata) -> Result<Vec<u8>> {
        let data = data.trim_end_matches(['\n', '\r']);
        if data.len() % 2 != 0 {
            anyhow::bail!("Invalid hex string: uneven number of characters");
        }
        data_encoding::HEXLOWER_PERMISSIVE
            .decode(data.as_bytes())
            .context("Invalid hex string")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::TestMetadata;

    #[test]
    fn test_hex_stream() {
        let result = HexStream
            .prettify(b"foo", &TestMetadata::default())
            .unwrap();
        assert_eq!(result, "666f6f");
    }

    #[test]
    fn test_hex_stream_empty() {
        let result = HexStream.prettify(b"", &TestMetadata::default()).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_hex_stream_reencode() {
        let data = "666f6f";
        let result = HexStream.reencode(data, &TestMetadata::default()).unwrap();
        assert_eq!(result, b"foo");
    }

    #[test]
    fn test_hex_stream_reencode_with_newlines() {
        let data = "666f6f\r\n";
        let result = HexStream.reencode(data, &TestMetadata::default()).unwrap();
        assert_eq!(result, b"foo");
    }

    #[test]
    fn test_hex_stream_reencode_uneven_chars() {
        let data = "666f6";
        let result = HexStream.reencode(data, &TestMetadata::default());
        assert!(result.is_err());
    }
}
