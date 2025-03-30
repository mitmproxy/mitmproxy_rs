use crate::contentviews::{Metadata, Prettify, Reencode};
use anyhow::{Context, Result};
use pretty_hex::{HexConfig, PrettyHex};
use std::num::ParseIntError;

pub struct HexStream;

impl Prettify for HexStream {
    fn name(&self) -> &'static str {
        "Hex Stream"
    }

    fn prettify(&self, data: &[u8], _metadata: &dyn Metadata) -> Result<String> {
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

    fn render_priority(&self, data: &[u8], _metadata: &dyn Metadata) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let ratio = data
            .iter()
            .take(100)
            .filter(|&&b| b < 9 || (13 < b && b < 32) || b > 126)
            .count() as f64
            / data.len().min(100) as f64;
        if ratio > 0.3 {
            1.0
        } else {
            0.0
        }
    }
}

impl Reencode for HexStream {
    fn reencode(&self, data: &str, _metadata: &dyn Metadata) -> Result<Vec<u8>> {
        (0..data.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&data[i..i + 2], 16))
            .collect::<Result<Vec<u8>, ParseIntError>>()
            .context("Invalid hex string")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contentviews::TestMetadata;

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
}
