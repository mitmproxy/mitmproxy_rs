use crate::{Metadata, Prettify, Protobuf, Reencode};
use anyhow::{bail, Context, Result};
use flate2::read::{DeflateDecoder, GzDecoder};
use mitmproxy_highlight::Language;
use serde::Deserialize;
use serde_yaml::Value;
use std::io::Read;

pub struct GRPC;

impl Prettify for GRPC {
    fn name(&self) -> &'static str {
        "gRPC"
    }

    fn syntax_highlight(&self) -> Language {
        Language::Yaml
    }

    fn prettify(&self, mut data: &[u8], metadata: &dyn Metadata) -> Result<String> {
        let mut protos = vec![];

        while !data.is_empty() {
            let compressed = match data[0] {
                0 => false,
                1 => true,
                _ => bail!("invalid gRPC: first byte is not a boolean"),
            };
            let len = match data.get(1..5) {
                Some(x) => u32::from_be_bytes(x.try_into()?) as usize,
                _ => bail!("invalid gRPC: first byte is not a boolean"),
            };
            let Some(proto) = data.get(5..5 + len) else {
                bail!("Invalid gRPC: not enough data")
            };

            let mut decompressed = Vec::new();
            let proto = if compressed {
                let encoding = metadata.get_header("grpc-encoding").unwrap_or_default();
                match encoding.as_str() {
                    "deflate" => {
                        let mut decoder = DeflateDecoder::new(proto);
                        decoder.read_to_end(&mut decompressed)?;
                        &decompressed
                    }
                    "gzip" => {
                        let mut decoder = GzDecoder::new(proto);
                        decoder.read_to_end(&mut decompressed)?;
                        &decompressed
                    }
                    "identity" => proto,
                    _ => bail!("unsupported compression: {}", encoding),
                }
            } else {
                proto
            };
            protos.push(Protobuf.prettify(proto, metadata)?);
            data = &data[5 + len..];
        }

        Ok(protos.join("\n---\n\n"))
    }

    fn render_priority(&self, _data: &[u8], metadata: &dyn Metadata) -> f64 {
        match metadata.content_type() {
            Some("application/grpc") => 1.0,
            Some("application/grpc+proto") => 1.0,
            Some("application/prpc") => 1.0,
            _ => 0.0,
        }
    }
}

impl Reencode for GRPC {
    fn reencode(&self, data: &str, metadata: &dyn Metadata) -> Result<Vec<u8>> {
        let mut ret = vec![];
        for document in serde_yaml::Deserializer::from_str(data) {
            let value = Value::deserialize(document).context("Invalid YAML")?;
            let proto = super::protobuf::reencode::reencode_yaml(value, metadata)?;
            ret.push(0); // uncompressed
            ret.extend(u32::to_be_bytes(proto.len() as u32));
            ret.extend(proto);
        }
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::TestMetadata;

    const TEST_YAML: &str = "1: 150\n\n---\n\n1: 150\n";
    const TEST_GRPC: &[u8] = &[
        0, 0, 0, 0, 3, 8, 150, 1, // first message
        0, 0, 0, 0, 3, 8, 150, 1, // second message
    ];

    const TEST_GZIP: &[u8] = &[
        1, 0, 0, 0, 23, // compressed flag and length
        31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 227, 152, 198, 8, 0, 160, 149, 78, 161, 3, 0, 0,
        0, // gzip data
    ];

    const TEST_DEFLATE: &[u8] = &[
        1, 0, 0, 0, 5, // compressed flag and length
        227, 152, 198, 8, 0, // deflate data
    ];

    #[test]
    fn test_empty() {
        let res = GRPC.prettify(&[], &TestMetadata::default()).unwrap();
        assert_eq!(res, "");
    }

    #[test]
    fn test_prettify_two_messages() {
        let res = GRPC.prettify(TEST_GRPC, &TestMetadata::default()).unwrap();
        assert_eq!(res, TEST_YAML);
    }

    #[test]
    fn test_prettify_gzip() {
        let metadata = TestMetadata::default().with_header("grpc-encoding", "gzip");
        let res = GRPC.prettify(TEST_GZIP, &metadata).unwrap();
        assert_eq!(res, "1: 150\n");
    }

    #[test]
    fn test_prettify_deflate() {
        let metadata = TestMetadata::default().with_header("grpc-encoding", "deflate");
        let res = GRPC.prettify(TEST_DEFLATE, &metadata).unwrap();
        assert_eq!(res, "1: 150\n");
    }

    #[test]
    fn test_reencode_two_messages() {
        let res = GRPC.reencode(TEST_YAML, &TestMetadata::default()).unwrap();
        assert_eq!(res, TEST_GRPC);
    }

    #[test]
    fn test_render_priority() {
        assert_eq!(
            GRPC.render_priority(
                b"",
                &TestMetadata::default().with_content_type("application/grpc")
            ),
            1.0
        );
        assert_eq!(
            GRPC.render_priority(
                b"",
                &TestMetadata::default().with_content_type("text/plain")
            ),
            0.0
        );
    }
}
