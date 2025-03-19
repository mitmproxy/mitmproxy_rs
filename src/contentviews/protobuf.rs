use crate::contentviews::{Prettify, PrettifyError};
use once_cell::sync::Lazy;
use protobuf::descriptor::{DescriptorProto, FileDescriptorProto};
use protobuf::reflect::FileDescriptor;
use protobuf::MessageDyn;
use protobuf::UnknownValueRef;
use regex::Captures;
use regex::Regex;
use serde_yaml::value::{Tag, TaggedValue};
use serde_yaml::{Mapping, Number, Sequence, Value};
use std::collections::HashMap;
use std::fmt::Write;

// Define static regular expressions for better performance
static FIXED32_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"!fixed32 (\d+)").unwrap());
static FIXED64_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"!fixed64 (\d+)").unwrap());
static VARINT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"!varint (\d+)").unwrap());

pub struct Protobuf;

impl Prettify for Protobuf {
    fn name(&self) -> &str {
        "Protocol Buffer"
    }

    fn prettify(&self, data: Vec<u8>) -> Result<String, PrettifyError> {
        // Check if data is empty first
        if data.is_empty() {
            return Err(PrettifyError::Generic("Empty protobuf data".to_string()));
        }

        // Create a dynamic message
        // TODO: Accept existing .proto files.
        let mut dynamic_message = Self::create_dynamic_message()?;

        // Parse protobuf and convert to YAML
        let yaml_value = self.parse_protobuf(data, &mut dynamic_message)?;

        // Convert the Value to prettified YAML
        let yaml_str = serde_yaml::to_string(&yaml_value)
            .map_err(|e| PrettifyError::Generic(format!("Failed to convert to YAML: {}", e)))?;

        // Apply regex replacements to transform the YAML output
        Self::apply_replacements(&yaml_str)
    }
}

impl Protobuf {
    // Helper method to create and return a dynamic message instance with no fields
    fn create_dynamic_message() -> Result<Box<dyn MessageDyn>, PrettifyError> {
        // Create a dynamic message with no fields to parse unknown fields
        let mut file_proto = FileDescriptorProto::new();
        file_proto.message_type.push({
            let mut message_type = DescriptorProto::new();
            message_type.set_name("Unknown".to_string());
            message_type
        });

        let file_descriptor = FileDescriptor::new_dynamic(file_proto, &[]).map_err(|e| {
            PrettifyError::Generic(format!("Failed to create dynamic message: {}", e))
        })?;

        let descriptor = file_descriptor
            .message_by_package_relative_name("Unknown")
            .ok_or_else(|| PrettifyError::Generic("Failed to get message by name".to_string()))?;

        Ok(descriptor.new_instance())
    }

    // Helper method to apply regex replacements to the YAML output
    fn apply_replacements(yaml_str: &str) -> Result<String, PrettifyError> {
        // Replace !fixed32 tags with comments showing float and i32 interpretations
        let with_fixed32 = FIXED32_RE.replace_all(yaml_str, |caps: &Captures| {
            let value = caps[1].parse::<u32>().unwrap_or_default();
            let float_value = f32::from_bits(value);
            let i32_value = value as i32;

            if !float_value.is_nan() && float_value < 0.0 {
                format!("{} # float: {}, i32: {}", value, float_value, i32_value)
            } else if !float_value.is_nan() {
                format!("{} # float: {}", value, float_value)
            } else if i32_value < 0 {
                format!("{} # i32: {}", value, i32_value)
            } else {
                value.to_string()
            }
        });

        // Replace !fixed64 tags with comments showing double and i64 interpretations
        let with_fixed64 = FIXED64_RE.replace_all(&with_fixed32, |caps: &Captures| {
            let value = caps[1].parse::<u64>().unwrap_or_default();
            let double_value = f64::from_bits(value);
            let i64_value = value as i64;

            if !double_value.is_nan() && double_value < 0.0 {
                format!("{} # double: {}, i64: {}", value, double_value, i64_value)
            } else if !double_value.is_nan() {
                format!("{} # double: {}", value, double_value)
            } else if i64_value < 0 {
                format!("{} # i64: {}", value, i64_value)
            } else {
                value.to_string()
            }
        });

        // Replace !varint tags with comments showing signed interpretation if different
        let with_varint = VARINT_RE.replace_all(&with_fixed64, |caps: &Captures| {
            let unsigned_value = caps[1].parse::<u64>().unwrap_or_default();
            let i64_zigzag = Self::decode_zigzag64(unsigned_value);

            // Only show signed value if it's different from unsigned
            if i64_zigzag < 0 {
                format!("{} # signed: {}", unsigned_value, i64_zigzag)
            } else {
                unsigned_value.to_string()
            }
        });

        Ok(with_varint.to_string())
    }

    // Decode a zigzag-encoded 64-bit integer
    fn decode_zigzag64(n: u64) -> i64 {
        ((n >> 1) as i64) ^ (-((n & 1) as i64))
    }

    // Convert length-delimited protobuf data to a hex string
    fn bytes_to_hex_string(bytes: &[u8]) -> String {
        let mut result = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(result, "{:02x}", b);
        }
        result
    }

    // Convert a single protobuf value to YAML
    fn convert_value_to_yaml(&self, value: &UnknownValueRef) -> Result<Value, PrettifyError> {
        match value {
            UnknownValueRef::Fixed32(v) => Ok(Value::Tagged(Box::new(TaggedValue {
                tag: Tag::new("fixed32"),
                value: Value::Number(Number::from(*v)),
            }))),
            UnknownValueRef::Fixed64(v) => Ok(Value::Tagged(Box::new(TaggedValue {
                tag: Tag::new("fixed64"),
                value: Value::Number(Number::from(*v)),
            }))),
            UnknownValueRef::Varint(v) => Ok(Value::Tagged(Box::new(TaggedValue {
                tag: Tag::new("varint"),
                value: Value::Number(Number::from(*v)),
            }))),
            UnknownValueRef::LengthDelimited(v) => self.process_length_delimited(v),
        }
    }

    // Process a length-delimited value (string, nested message, or binary)
    fn process_length_delimited(&self, data: &[u8]) -> Result<Value, PrettifyError> {
        // Try to parse as a string first
        if let Ok(s) = std::str::from_utf8(data) {
            if s.chars()
                .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            {
                return Ok(Value::String(s.to_string()));
            }
        }

        // Try to parse as a nested message
        let mut nested_message = Self::create_dynamic_message()?;
        if let Ok(nested_yaml) = self.parse_protobuf(data.to_vec(), &mut nested_message) {
            return Ok(nested_yaml);
        }

        // If not a string or nested message, format as binary data with YAML tag
        let hex_string = Self::bytes_to_hex_string(data);
        Ok(Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("Binary"),
            value: Value::String(hex_string),
        })))
    }

    // Helper method to parse protobuf data and process unknown fields to convert to YAML
    fn parse_protobuf(
        &self,
        data: Vec<u8>,
        dynamic_message: &mut Box<dyn MessageDyn>,
    ) -> Result<Value, PrettifyError> {
        // Parse the protobuf data using the provided dynamic message
        dynamic_message
            .merge_from_bytes_dyn(&data)
            .map_err(|e| PrettifyError::Generic(format!("Failed to parse protobuf: {}", e)))?;

        // Get unknown fields & group by field id.
        let unknown_fields = dynamic_message.unknown_fields_dyn();
        let mut field_groups: HashMap<u32, Vec<UnknownValueRef>> = HashMap::new();
        for (field_number, value) in unknown_fields.iter() {
            field_groups.entry(field_number).or_default().push(value);
        }

        // Convert unknown fields to a YAML value
        let mut root = Mapping::new();
        for (field_number, values) in field_groups {
            let key = Value::Number(Number::from(field_number));
            let value = if values.len() == 1 {
                self.convert_value_to_yaml(&values[0])?
            } else {
                Value::Sequence(
                    values
                        .into_iter()
                        .map(|x| self.convert_value_to_yaml(&x))
                        .collect::<Result<Sequence, PrettifyError>>()?,
                )
            };
            root.insert(key, value);
        }
        Ok(Value::Mapping(root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Varint tests
    #[test]
    fn test_varint() {
        // From docs: field 1: varint 150
        const PROTO: &[u8] = &[0x08, 0x96, 0x01];
        let result = Protobuf.prettify(PROTO.to_vec()).unwrap();
        assert_eq!(result, "1: 150\n");
    }

    #[test]
    fn test_varint_signed() {
        // field 1: varint 11 (zigzag encoded: -6)
        const PROTO: &[u8] = &[0x08, 0x0B];
        let result = Protobuf.prettify(PROTO.to_vec()).unwrap();
        assert_eq!(result, "1: 11 # signed: -6\n");
    }

    #[test]
    fn test_repeated_numeric() {
        // Example based on docs: repeated field 1 with values 1, 2, 3
        const PROTO: &[u8] = &[0x08, 0x01, 0x08, 0x02, 0x08, 0x03];
        let result = Protobuf.prettify(PROTO.to_vec()).unwrap();
        assert_eq!(result, "1:\n- 1 # signed: -1\n- 2\n- 3 # signed: -2\n");
    }

    #[test]
    fn test_packed_repeated() {
        // From docs: "message Test5 { repeated int32 f = 6 [packed=true]; }"
        // With values 3, 270, and 86942
        const PROTO: &[u8] = &[0x32, 0x06, 0x03, 0x8E, 0x02, 0x9E, 0xA7, 0x05];
        let result = Protobuf.prettify(PROTO.to_vec()).unwrap();
        // Our implementation shows this as binary data as we don't have schema info
        assert_eq!(result, "6: !Binary 038e029ea705\n");
    }

    // Fixed32 tests
    #[test]
    fn test_fixed32() {
        const PROTO: &[u8] = &[0x15, 0x00, 0x00, 0x80, 0xBF];
        let result = Protobuf.prettify(PROTO.to_vec()).unwrap();
        assert_eq!(result, "2: 3212836864 # float: -1, i32: -1082130432\n");
    }

    #[test]
    fn test_fixed32_positive() {
        const PROTO: &[u8] = &[0x15, 0xD0, 0x0F, 0x49, 0x40];
        let result = Protobuf.prettify(PROTO.to_vec()).unwrap();
        assert_eq!(result, "2: 1078530000 # float: 3.14159\n");
    }

    #[test]
    fn test_fixed32_no_float() {
        const PROTO: &[u8] = &[0x15, 0xFF, 0xFF, 0xFF, 0xFF];
        let result = Protobuf.prettify(PROTO.to_vec()).unwrap();
        assert_eq!(result, "2: 4294967295 # i32: -1\n");
    }

    #[test]
    fn test_fixed32_positive_no_float() {
        const PROTO: &[u8] = &[0x15, 0x01, 0x00, 0xC0, 0x7F];
        let result = Protobuf.prettify(PROTO.to_vec()).unwrap();
        assert_eq!(result, "2: 2143289345\n");
    }

    // Fixed64 tests
    #[test]
    fn test_fixed64() {
        const PROTO: &[u8] = &[0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0xBF];
        let result = Protobuf.prettify(PROTO.to_vec()).unwrap();
        assert_eq!(
            result,
            "3: 13830554455654793216 # double: -1, i64: -4616189618054758400\n"
        );
    }

    #[test]
    fn test_fixed64_positive() {
        const PROTO: &[u8] = &[0x19, 0x6E, 0x86, 0x1B, 0xF0, 0xF9, 0x21, 0x09, 0x40];
        let result = Protobuf.prettify(PROTO.to_vec()).unwrap();
        assert_eq!(result, "3: 4614256650576692846 # double: 3.14159\n");
    }

    #[test]
    fn test_fixed64_no_float() {
        const PROTO: &[u8] = &[0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let result = Protobuf.prettify(PROTO.to_vec()).unwrap();
        assert_eq!(result, "3: 18446744073709551615 # i64: -1\n");
    }

    #[test]
    fn test_fixed64_positive_no_float() {
        const PROTO: &[u8] = &[0x19, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x7F];
        let result = Protobuf.prettify(PROTO.to_vec()).unwrap();
        assert_eq!(result, "3: 9221120237041090561\n");
    }

    // String field test
    #[test]
    fn test_string_field() {
        // field 4: string "hello" (LEN type field from docs)
        const PROTO: &[u8] = &[0x22, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F];
        let result = Protobuf.prettify(PROTO.to_vec()).unwrap();
        assert_eq!(result, "4: hello\n");
    }

    #[test]
    fn test_nested_message() {
        // From docs about nested messages: field 5 with a nested message containing field 1: varint 42
        const PROTO: &[u8] = &[0x2A, 0x02, 0x08, 0x2A];
        let result = Protobuf.prettify(PROTO.to_vec()).unwrap();
        assert_eq!(result, "5:\n  1: 42\n");
    }

    #[test]
    fn test_binary_data() {
        // Binary data example: field 6: binary data [0x01, 0x02, 0x03]
        const PROTO: &[u8] = &[0x32, 0x03, 0x01, 0x02, 0x03];
        let result = Protobuf.prettify(PROTO.to_vec()).unwrap();
        assert_eq!(result, "6: !Binary '010203'\n");
    }

    #[test]
    fn test_invalid_protobuf() {
        let result = Protobuf.prettify(vec![0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_protobuf() {
        let result = Protobuf.prettify(vec![]);
        assert!(result.is_err());
    }
}
