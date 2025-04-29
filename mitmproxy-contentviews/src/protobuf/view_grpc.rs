use super::{existing_proto_definitions, reencode};
use crate::protobuf::existing_proto_definitions::DescriptorWithDeps;
use crate::{Metadata, Prettify, Protobuf, Reencode};
use anyhow::{bail, Context, Result};
use flate2::read::{DeflateDecoder, GzDecoder};
use log::info;
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

    fn prettify(&self, data: &[u8], metadata: &dyn Metadata) -> Result<String> {
        let encoding = metadata.get_header("grpc-encoding").unwrap_or_default();
        let proto_def = existing_proto_definitions::find_best_match(metadata)?;
        if let Some(descriptor) = &proto_def {
            if let Ok(ret) = self.prettify_with_descriptor(data, &encoding, descriptor) {
                return Ok(ret);
            }
        }
        let ret = self.prettify_with_descriptor(data, &encoding, &DescriptorWithDeps::default())?;
        if proto_def.is_some() {
            info!("Existing gRPC definition does not match, parsing as unknown proto.");
        }
        Ok(ret)
    }

    fn render_priority(&self, _data: &[u8], metadata: &dyn Metadata) -> f32 {
        match metadata.content_type() {
            Some("application/grpc") => 1.0,
            Some("application/grpc+proto") => 1.0,
            Some("application/prpc") => 1.0,
            _ => 0.0,
        }
    }
}

impl GRPC {
    fn prettify_with_descriptor(
        &self,
        mut data: &[u8],
        encoding: &str,
        descriptor: &DescriptorWithDeps,
    ) -> Result<String> {
        let mut protos = vec![];
        while !data.is_empty() {
            let compressed = match data[0] {
                0 => false,
                1 => true,
                _ => bail!("invalid gRPC: first byte is not a boolean"),
            };
            let len = match data.get(1..5) {
                Some(x) => u32::from_be_bytes(x.try_into()?) as usize,
                _ => bail!("invalid gRPC: not enough bytes"),
            };
            let Some(proto) = data.get(5..5 + len) else {
                bail!("Invalid gRPC: not enough data")
            };

            let mut decompressed = Vec::new();
            let proto = if compressed {
                match encoding {
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
            protos.push(Protobuf.prettify_with_descriptor(proto, descriptor)?);
            data = &data[5 + len..];
        }

        Ok(protos.join("\n---\n\n"))
    }
}

impl Reencode for GRPC {
    fn reencode(&self, data: &str, metadata: &dyn Metadata) -> Result<Vec<u8>> {
        let descriptor = existing_proto_definitions::find_best_match(metadata)?
            .unwrap_or_default()
            .descriptor;
        let mut ret = vec![];
        for document in serde_yaml::Deserializer::from_str(data) {
            let value = Value::deserialize(document).context("Invalid YAML")?;
            let proto = reencode::reencode_yaml(value, &descriptor)?;
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

    const TEST_YAML: &str = "1: 150  # !sint: 75\n\n---\n\n1: 150  # !sint: 75\n";
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
        assert_eq!(res, "1: 150  # !sint: 75\n");
    }

    #[test]
    fn test_prettify_deflate() {
        let metadata = TestMetadata::default().with_header("grpc-encoding", "deflate");
        let res = GRPC.prettify(TEST_DEFLATE, &metadata).unwrap();
        assert_eq!(res, "1: 150  # !sint: 75\n");
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

    mod existing_definition {
        use super::*;

        const TEST_YAML_KNOWN: &str = "example: 150\n\n---\n\nexample: 150\n";

        #[test]
        fn existing_proto() {
            let metadata = TestMetadata::default().with_protobuf_definitions(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/testdata/protobuf/simple.proto"
            ));
            let res = GRPC.prettify(TEST_GRPC, &metadata).unwrap();
            assert_eq!(res, TEST_YAML_KNOWN);
        }

        #[test]
        fn existing_service_request() {
            let metadata = TestMetadata::default()
                .with_is_http_request(true)
                .with_path("/Service/Method")
                .with_protobuf_definitions(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/testdata/protobuf/simple_service.proto"
                ));
            let req = GRPC.prettify(TEST_GRPC, &metadata).unwrap();
            assert_eq!(req, TEST_YAML);
        }

        #[test]
        fn existing_service_response() {
            let metadata = TestMetadata::default()
                .with_is_http_request(false)
                .with_path("/Service/Method")
                .with_protobuf_definitions(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/testdata/protobuf/simple_service.proto"
                ));
            let req = GRPC.prettify(TEST_GRPC, &metadata).unwrap();
            assert_eq!(req, TEST_YAML_KNOWN);
        }

        #[test]
        fn existing_package() {
            let metadata = TestMetadata::default()
                .with_path("/example.simple.Service/Method")
                .with_protobuf_definitions(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/testdata/protobuf/simple_package.proto"
                ));
            let req = GRPC.prettify(TEST_GRPC, &metadata).unwrap();
            assert_eq!(req, TEST_YAML_KNOWN);
        }

        #[test]
        fn existing_nested() {
            let metadata = TestMetadata::default()
                .with_path("/example.nested.Service/Method")
                .with_protobuf_definitions(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/testdata/protobuf/nested.proto"
                ));
            let req = GRPC.prettify(TEST_GRPC, &metadata).unwrap();
            assert_eq!(req, TEST_YAML_KNOWN);
        }

        /// When the existing proto definition does not match the wire data,
        /// but the wire data is still valid Protobuf, parse it raw.
        #[test]
        fn existing_mismatch() {
            let metadata = TestMetadata::default().with_protobuf_definitions(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/testdata/protobuf/mismatch.proto"
            ));
            let res = GRPC.prettify(TEST_GRPC, &metadata).unwrap();
            assert_eq!(res, TEST_YAML);
        }
    }
}
