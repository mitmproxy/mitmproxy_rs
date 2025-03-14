use crate::contentviews::{Prettify, PrettifyError, Reencode, ReencodeError};
use rmp_serde::{decode, encode};
use serde_yaml;

pub struct MsgPack;

impl Prettify for MsgPack {
    fn name(&self) -> &'static str {
        "MsgPack"
    }

    fn prettify(&self, data: Vec<u8>) -> Result<String, PrettifyError> {
        // Deserialize MsgPack to a serde_yaml::Value
        let value: serde_yaml::Value = decode::from_slice(&data)
            .map_err(|e| PrettifyError::Generic(format!("Failed to deserialize MsgPack: {}", e)))?;

        // Convert the Value to prettified YAML
        serde_yaml::to_string(&value)
            .map_err(|e| PrettifyError::Generic(format!("Failed to convert to YAML: {}", e)))
    }
}

impl Reencode for MsgPack {
    fn reencode(&self, data: String) -> anyhow::Result<Vec<u8>, ReencodeError> {
        // Parse the YAML string to a serde_yaml::Value
        let value: serde_yaml::Value = serde_yaml::from_str(&data)
            .map_err(|e| ReencodeError::InvalidFormat(format!("Invalid YAML: {}", e)))?;

        // Serialize the Value to MsgPack
        let mut buf = Vec::new();
        encode::write_named(&mut buf, &value).map_err(|e| {
            ReencodeError::InvalidFormat(format!("Failed to encode to MsgPack: {}", e))
        })?;

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let result = MsgPack.prettify(TEST_MSGPACK.to_vec()).unwrap();
        assert_eq!(result, TEST_YAML);
    }

    #[test]
    fn test_msgpack_serialize() {
        let yaml_data = TEST_YAML.to_string();

        let result = MsgPack.reencode(yaml_data).unwrap();

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
        // Start with the hardcoded MsgPack data
        let msgpack_data = TEST_MSGPACK.to_vec();

        // Deserialize to YAML
        let yaml_result = MsgPack.prettify(msgpack_data).unwrap();

        // Serialize back to MsgPack
        let result = MsgPack.reencode(yaml_result).unwrap();

        // Deserialize both the original and the result to Values for comparison
        let original_value: serde_yaml::Value = decode::from_slice(TEST_MSGPACK).unwrap();
        let result_value: serde_yaml::Value = decode::from_slice(&result).unwrap();

        // Compare the values
        assert_eq!(original_value, result_value);
    }
}
