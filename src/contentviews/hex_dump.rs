use crate::contentviews::{Metadata, Prettify};
use pretty_hex::{HexConfig, PrettyHex};

pub struct HexDump;

impl Prettify for HexDump {
    fn name(&self) -> &'static str {
        "Hex Dump"
    }

    fn prettify(&self, data: &[u8], _metadata: &dyn Metadata) -> anyhow::Result<String> {
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
    use crate::contentviews::TestMetadata;

    #[test]
    fn prettify_simple() {
        let result = HexDump.prettify(b"abcd", &TestMetadata::default()).unwrap();
        assert_eq!(
            result,
            "0000:   61 62 63 64                                          abcd"
        );
    }

    #[test]
    fn prettify_empty() {
        let result = HexDump.prettify(b"", &TestMetadata::default()).unwrap();
        assert_eq!(result, "");
    }
}
