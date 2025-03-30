use crate::contentviews::Prettify;
use pretty_hex::{HexConfig, PrettyHex};

pub struct HexDump;

impl Prettify for HexDump {
    fn name(&self) -> &'static str {
        "Hex Dump"
    }

    fn prettify(&self, data: &[u8]) -> anyhow::Result<String> {
        Ok(format!(
            "{:?}",
            data.hex_conf(HexConfig {
                title: false,
                ascii: true,
                width: 16,
                group: 4,
                chunk: 1,
                max_bytes: usize::MAX,
                display_offset: 0,
            })
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hexdump_deserialize() {
        let result = HexDump.prettify(b"abcd").unwrap();
        assert_eq!(
            result,
            "0000:   61 62 63 64                                          abcd"
        );
    }

    #[test]
    fn test_hexdump_deserialize_empty() {
        let result = HexDump.prettify(b"").unwrap();
        assert_eq!(result, "");
    }
}
