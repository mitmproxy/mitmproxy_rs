use super::{Metadata, Prettify, Reencode};
use anyhow::{Context, Result};
use mitmproxy_highlight::Language;
use rmp_serde::{decode, encode};

pub struct MsgPack;

impl Prettify for MsgPack {
    fn name(&self) -> &'static str {
        "MsgPack"
    }

    fn syntax_highlight(&self) -> Language {
        Language::Yaml
    }

    fn prettify(&self, data: &[u8], _metadata: &dyn Metadata) -> Result<String> {
        // Deserialize MsgPack to a serde_yaml::Value
        let value: serde_yaml::Value =
            decode::from_slice(data).context("Failed to deserialize MsgPack")?;

        // Convert the Value to prettified YAML
        serde_yaml::to_string(&value).context("Failed to convert to YAML")
    }

    fn render_priority(&self, _data: &[u8], metadata: &dyn Metadata) -> f32 {
        match metadata.content_type() {
            Some("application/msgpack") => 1.0,
            Some("application/x-msgpack") => 1.0,
            _ => 0.0,
        }
    }
}

impl Reencode for MsgPack {
    fn reencode(&self, data: &str, _metadata: &dyn Metadata) -> Result<Vec<u8>> {
        // Parse the YAML string to a serde_yaml::Value
        let value: serde_yaml::Value = serde_yaml::from_str(data).context("Invalid YAML")?;

        // Serialize the Value to MsgPack
        let mut buf = Vec::new();
        encode::write_named(&mut buf, &value).context("Failed to encode to MsgPack")?;

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::TestMetadata;

    // Hardcoded MsgPack data for a simple object:
    // {
    //   "name": "John Doe",
    //   "age": 30,
    //   "tags": ["developer", "rust"]
    // }
    const TEST_MSGPACK: &[u8] = &[
        0x83, // map with 3 elements
        0xa4, 0x6e, 0x61, 0x6d, 0x65, // "name"
        0xa8, 0x4a, 0x6f, 0x68, 0x6e, 0x20, 0x44, 0x6f, 0x65, // "John Doe"
        0xa3, 0x61, 0x67, 0x65, // "age"
        0x1e, // 30
        0xa4, 0x74, 0x61, 0x67, 0x73, // "tags"
        0x92, // array with 2 elements
        0xa9, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x72, // "developer"
        0xa4, 0x72, 0x75, 0x73, 0x74, // "rust"
    ];

    // Expected YAML representation
    const TEST_YAML: &str = r#"name: John Doe
age: 30
tags:
- developer
- rust
"#;

    #[test]
    fn test_msgpack_deserialize() {
        let result = MsgPack
            .prettify(TEST_MSGPACK, &TestMetadata::default())
            .unwrap();
        assert_eq!(result, TEST_YAML);
    }

    #[test]
    fn test_msgpack_serialize() {
        let result = MsgPack
            .reencode(TEST_YAML, &TestMetadata::default())
            .unwrap();

        // Verify the MsgPack data contains the expected values
        let value: serde_yaml::Value = decode::from_slice(&result).unwrap();

        if let serde_yaml::Value::Mapping(map) = value {
            assert_eq!(
                map.get(serde_yaml::Value::String("name".to_string())),
                Some(&serde_yaml::Value::String("John Doe".to_string()))
            );

            assert_eq!(
                map.get(serde_yaml::Value::String("age".to_string())),
                Some(&serde_yaml::Value::Number(serde_yaml::Number::from(30)))
            );

            if let Some(serde_yaml::Value::Sequence(tags)) =
                map.get(serde_yaml::Value::String("tags".to_string()))
            {
                assert_eq!(tags.len(), 2);
                assert_eq!(tags[0], serde_yaml::Value::String("developer".to_string()));
                assert_eq!(tags[1], serde_yaml::Value::String("rust".to_string()));
            } else {
                panic!("tags is not a sequence");
            }
        } else {
            panic!("value is not a mapping");
        }
    }

    #[test]
    fn test_msgpack_roundtrip() {
        // Deserialize to YAML
        let yaml_result = MsgPack
            .prettify(TEST_MSGPACK, &TestMetadata::default())
            .unwrap();

        // Serialize back to MsgPack
        let result = MsgPack
            .reencode(&yaml_result, &TestMetadata::default())
            .unwrap();

        // Deserialize both the original and the result to Values for comparison
        let original_value: serde_yaml::Value = decode::from_slice(TEST_MSGPACK).unwrap();
        let result_value: serde_yaml::Value = decode::from_slice(&result).unwrap();

        // Compare the values
        assert_eq!(original_value, result_value);
    }

    #[test]
    fn test_invalid_yaml() {
        let err = MsgPack
            .reencode("@invalid_yaml", &TestMetadata::default())
            .unwrap_err();
        assert_eq!(format!("{err}"), "Invalid YAML");
    }
}
