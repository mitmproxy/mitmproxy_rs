use crate::protobuf::raw_to_proto::new_empty_descriptor;
use crate::protobuf::{proto_to_yaml, raw_to_proto, reencode, yaml_to_pretty};
use crate::{Metadata, Prettify, Reencode};
use anyhow::{Context, Result};
use mitmproxy_highlight::Language;
use protobuf::reflect::{FileDescriptor, MessageDescriptor};
use serde_yaml::Value;

pub(super) mod tags {
    use regex::Regex;
    use serde_yaml::value::Tag;
    use std::sync::LazyLock;

    pub static BINARY: LazyLock<Tag> = LazyLock::new(|| Tag::new("binary"));
    pub static VARINT: LazyLock<Tag> = LazyLock::new(|| Tag::new("varint"));
    pub static FIXED32: LazyLock<Tag> = LazyLock::new(|| Tag::new("fixed32"));
    pub static FIXED64: LazyLock<Tag> = LazyLock::new(|| Tag::new("fixed64"));

    pub static VARINT_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(&format!(r"{} (\d+)", *VARINT)).unwrap());
    pub static FIXED32_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(&format!(r"{} (\d+)", *FIXED32)).unwrap());
    pub static FIXED64_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(&format!(r"{} (\d+)", *FIXED64)).unwrap());
}

pub struct Protobuf;

impl Prettify for Protobuf {
    fn name(&self) -> &str {
        "Protobuf"
    }

    fn syntax_highlight(&self) -> Language {
        Language::Yaml
    }

    fn prettify(&self, data: &[u8], _metadata: &dyn Metadata) -> Result<String> {
        // FIXME use new create_new
        self.prettify_with_descriptor(data, &new_empty_descriptor(None, "Unknown"), &[])
    }

    fn render_priority(&self, _data: &[u8], metadata: &dyn Metadata) -> f64 {
        match metadata.content_type() {
            Some("application/x-protobuf") => 1.0,
            Some("application/x-protobuffer") => 1.0,
            _ => 0.0,
        }
    }
}

impl Protobuf {
    pub(super) fn prettify_with_descriptor(
        &self,
        data: &[u8],
        descriptor: &MessageDescriptor,
        dependencies: &[FileDescriptor],
    ) -> Result<String> {
        // Check if data is empty first
        if data.is_empty() {
            return Ok("{}  # empty protobuf message".to_string());
        }

        let descriptor = raw_to_proto::merge_proto_and_descriptor(data, descriptor, dependencies)?;

        // Parse protobuf and convert to YAML
        let message = descriptor
            .parse_from_bytes(data)
            .context("Error parsing protobuf")?;
        let yaml_value = proto_to_yaml::message_to_yaml(message.as_ref());

        let yaml_str = serde_yaml::to_string(&yaml_value).context("Failed to convert to YAML")?;
        yaml_to_pretty::apply_replacements(&yaml_str)
    }
}

impl Reencode for Protobuf {
    fn reencode(&self, data: &str, metadata: &dyn Metadata) -> Result<Vec<u8>> {
        let value: Value = serde_yaml::from_str(data).context("Invalid YAML")?;
        reencode::reencode_yaml(value, metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::TestMetadata;

    macro_rules! test_roundtrip {
        ($name:ident,$proto:literal,$yaml:literal) => {
            mod $name {
                use super::*;

                pub(super) const PROTO: &[u8] = $proto;
                pub(super) const YAML: &str = $yaml;

                #[test]
                fn prettify() {
                    let result = Protobuf.prettify(PROTO, &TestMetadata::default()).unwrap();
                    assert_eq!(result, YAML);
                }

                #[test]
                fn reencode() {
                    let result = Protobuf.reencode(YAML, &TestMetadata::default()).unwrap();
                    assert_eq!(result, PROTO);
                }
            }
        };
    }

    test_roundtrip!(varint, b"\x08\x96\x01", "1: 150\n");
    test_roundtrip!(varint_negative, b"\x08\x0B", "1: 11 # signed: -6\n");
    test_roundtrip!(binary, b"\x32\x03\x01\x02\x03", "6: !binary '010203'\n");
    test_roundtrip!(string, b"\x0A\x05\x68\x65\x6C\x6C\x6F", "1: hello\n");
    test_roundtrip!(nested, b"\x2A\x02\x08\x2A", "5:\n  1: 42\n");
    test_roundtrip!(
        nested_twice,
        b"\x2A\x04\x2A\x02\x08\x2A",
        "5:\n  5:\n    1: 42\n"
    );
    test_roundtrip!(
        fixed64,
        b"\x19\x00\x00\x00\x00\x00\x00\xF0\xBF",
        "3: !fixed64 13830554455654793216 # double: -1, i64: -4616189618054758400\n"
    );
    test_roundtrip!(
        fixed64_positive,
        b"\x19\x6E\x86\x1B\xF0\xF9\x21\x09\x40",
        "3: !fixed64 4614256650576692846 # double: 3.14159\n"
    );
    test_roundtrip!(
        fixed64_no_float,
        b"\x19\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        "3: !fixed64 18446744073709551615 # i64: -1\n"
    );
    test_roundtrip!(
        fixed64_positive_no_float,
        b"\x19\x01\x00\x00\x00\x00\x00\xF8\x7F",
        "3: !fixed64 9221120237041090561\n"
    );
    test_roundtrip!(
        fixed32,
        b"\x15\x00\x00\x80\xBF",
        "2: !fixed32 3212836864 # float: -1, i32: -1082130432\n"
    );
    test_roundtrip!(
        fixed32_positive,
        b"\x15\xD0\x0F\x49\x40",
        "2: !fixed32 1078530000 # float: 3.14159\n"
    );
    test_roundtrip!(
        fixed32_no_float,
        b"\x15\xFF\xFF\xFF\xFF",
        "2: !fixed32 4294967295 # i32: -1\n"
    );
    test_roundtrip!(
        fixed32_positive_no_float,
        b"\x15\x01\x00\xC0\x7F",
        "2: !fixed32 2143289345\n"
    );
    // From docs: "message Test5 { repeated int32 f = 6 [packed=true]; }"
    // With values 3, 270, and 86942
    test_roundtrip!(
        repeated_packed,
        b"\x32\x06\x03\x8E\x02\x9E\xA7\x05",
        "6: !binary 038e029ea705\n"
    );
    test_roundtrip!(
        repeated_varint,
        b"\x08\x01\x08\x02\x08\x03",
        "1:\n- 1 # signed: -1\n- 2\n- 3 # signed: -2\n"
    );

    mod reencode {
        use super::*;

        #[test]
        fn reencode_new_nested_message() {
            let result = Protobuf
                .reencode(nested::YAML, &TestMetadata::default())
                .unwrap();
            assert_eq!(result, nested::PROTO);
        }

        #[test]
        fn new_string_attr() {
            let result = Protobuf
                .reencode(string::YAML, &TestMetadata::default())
                .unwrap();
            assert_eq!(result, string::PROTO);
        }
    }

    #[test]
    fn test_invalid_protobuf() {
        let result = Protobuf.prettify(b"\xFF\xFF", &TestMetadata::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_no_crash() {
        let result = Protobuf.prettify(
            b"\n\x13gRPC testing server\x12\x07\n\x05Index\x12\x07\n\x05Empty\x12\x0c\n\nDummyUnary\x12\x0f\n\rSpecificError\x12\r\n\x0bRandomError\x12\x0e\n\x0cHeadersUnary\x12\x11\n\x0fNoResponseUnary",
            &TestMetadata::default()).unwrap();
        assert_eq!(result,  "1: gRPC testing server\n2:\n- 1: Index\n- 1: Empty\n- 1: DummyUnary\n- 1: SpecificError\n- 1: RandomError\n- 1: HeadersUnary\n- 1: NoResponseUnary\n");
    }

    #[test]
    fn test_empty_protobuf() {
        let result = Protobuf.prettify(b"", &TestMetadata::default()).unwrap();
        assert_eq!(result, "{}  # empty protobuf message");
    }
}
