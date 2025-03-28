use crate::contentviews::{Prettify, PrettifyError, Reencode, ReencodeError};
use once_cell::sync::Lazy;
use protobuf::descriptor::field_descriptor_proto::Label::LABEL_REPEATED;
use protobuf::descriptor::field_descriptor_proto::Type;
use protobuf::descriptor::field_descriptor_proto::Type::{
    TYPE_BYTES, TYPE_FIXED32, TYPE_FIXED64, TYPE_STRING, TYPE_UINT64,
};
use protobuf::descriptor::{DescriptorProto, FieldDescriptorProto, FileDescriptorProto};
use protobuf::reflect::{
    FieldDescriptor, FileDescriptor, MessageDescriptor, ReflectFieldRef, ReflectValueRef,
    RuntimeFieldType, RuntimeType,
};
use protobuf::well_known_types::empty::Empty;
use protobuf::UnknownValueRef;
use protobuf::{EnumOrUnknown, Message, MessageDyn, MessageFull, UnknownValue};
use regex::Captures;
use regex::Regex;
use serde_yaml::value::{Tag, TaggedValue};
use serde_yaml::Value::Tagged;
use serde_yaml::{Mapping, Number, Value};
use std::collections::BTreeMap;
use std::fmt::Write;
use std::num::ParseIntError;
use std::ops::Deref;
use std::str::FromStr;

// Define static regular expressions for better performance
static FIXED32_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"!fixed32 (\d+)").unwrap());
static FIXED64_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"!fixed64 (\d+)").unwrap());
static VARINT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"!varint (\d+)").unwrap());

pub struct Protobuf;

enum GuessedFieldType {
    String,
    Message(Box<DescriptorProto>),
    Unknown,
}

impl Prettify for Protobuf {
    fn name(&self) -> &str {
        "Protocol Buffer"
    }

    fn prettify(&self, data: Vec<u8>) -> Result<String, PrettifyError> {
        // Check if data is empty first
        if data.is_empty() {
            return Err(PrettifyError::Generic("Empty protobuf data".to_string()));
        }

        let existing = Empty::descriptor();
        let descriptor = Self::create_descriptor(&data, existing)?;

        let message = descriptor
            .parse_from_bytes(&data)
            .map_err(|e| PrettifyError::Generic(format!("Error parsing protobuf: {e}")))?;

        // Parse protobuf and convert to YAML
        let yaml_value = Self::message_to_yaml(message.as_ref());

        // Convert the Value to prettified YAML
        let yaml_str = serde_yaml::to_string(&yaml_value)
            .map_err(|e| PrettifyError::Generic(format!("Failed to convert to YAML: {}", e)))?;

        // Apply regex replacements to transform the YAML output
        Self::apply_replacements(&yaml_str)
    }
}

impl Reencode for Protobuf {
    fn reencode(&self, data: &str, original: &[u8]) -> Result<Vec<u8>, ReencodeError> {
        let existing = Empty::descriptor();
        let descriptor = Self::create_descriptor(original, existing)
            .map_err(|e| ReencodeError::InvalidFormat(format!("{e}")))?;
        let message = descriptor.new_instance();

        let value: Value = serde_yaml::from_str(data)
            .map_err(|e| ReencodeError::InvalidFormat(format!("invalid yaml: {e}")))?;

        Self::merge_yaml_into_message(value, message)
    }
}

fn tag_number(value: Value, field_type: Type) -> Value {
    match field_type {
        TYPE_UINT64 => Tagged(Box::new(TaggedValue {
            tag: Tag::new("varint"),
            value,
        })),
        TYPE_FIXED64 => Tagged(Box::new(TaggedValue {
            tag: Tag::new("fixed64"),
            value,
        })),
        TYPE_FIXED32 => Tagged(Box::new(TaggedValue {
            tag: Tag::new("fixed32"),
            value,
        })),
        _ => value,
    }
}

fn int_value(n: Number, field: Option<&FieldDescriptor>) -> UnknownValue {
    if let Some(field) = field {
        if let Some(typ) = field.proto().type_.and_then(|t| t.enum_value().ok()) {
            match typ {
                TYPE_FIXED64 | Type::TYPE_SFIXED64 | Type::TYPE_DOUBLE => {
                    return if let Some(n) = n.as_u64() {
                        UnknownValue::Fixed64(n)
                    } else if let Some(n) = n.as_i64() {
                        UnknownValue::sfixed64(n)
                    } else {
                        UnknownValue::double(n.as_f64().expect("as_f64 never fails"))
                    }
                }
                TYPE_FIXED32 | Type::TYPE_SFIXED32 | Type::TYPE_FLOAT => {
                    return if let Some(n) = n.as_u64() {
                        UnknownValue::Fixed32(n as u32)
                    } else if let Some(n) = n.as_i64() {
                        UnknownValue::sfixed32(n as i32)
                    } else {
                        UnknownValue::float(n.as_f64().expect("as_f64 never fails") as f32)
                    }
                }
                _ => (),
            }
        }
    }
    if let Some(n) = n.as_u64() {
        UnknownValue::Varint(n)
    } else if let Some(n) = n.as_i64() {
        UnknownValue::int64(n)
    } else {
        UnknownValue::double(n.as_f64().expect("as_f64 never fails"))
    }
}

impl Protobuf {
    fn merge_yaml_into_message(
        value: Value,
        mut message: Box<dyn MessageDyn>,
    ) -> Result<Vec<u8>, ReencodeError> {
        let Value::Mapping(mapping) = value else {
            return Err(ReencodeError::InvalidFormat(
                "yaml is not a mapping".to_string(),
            ));
        };

        for (key, value) in mapping.into_iter() {
            let field_num = match key {
                Value::String(key) => {
                    if let Some(field) = message.descriptor_dyn().field_by_name(&key) {
                        field.number()
                    } else if let Ok(field_num) = i32::from_str(&key) {
                        field_num
                    } else {
                        return Err(ReencodeError::InvalidFormat(format!(
                            "unknown protobuf field key: {key}"
                        )));
                    }
                }
                Value::Number(key) => {
                    let Some(field_num) = key.as_i64() else {
                        return Err(ReencodeError::InvalidFormat(format!(
                            "invalid protobuf field number: {key}"
                        )));
                    };
                    field_num as i32
                }
                other => {
                    return Err(ReencodeError::InvalidFormat(format!(
                        "unexpected key: {other:?}"
                    )))
                }
            } as u32;

            Self::add_field(message.as_mut(), field_num, value)?;
        }

        message
            .write_to_bytes_dyn()
            .map_err(|e| ReencodeError::InvalidFormat(format!("failed to serialize protobuf: {e}")))
    }

    fn add_field(
        message: &mut dyn MessageDyn,
        field_num: u32,
        value: Value,
    ) -> Result<(), ReencodeError> {
        let value = match value {
            Value::Null => return Ok(()),
            Value::Sequence(seq) => {
                for s in seq.into_iter() {
                    Self::add_field(message, field_num, s)?;
                }
                return Ok(());
            }
            Tagged(t) => {
                if t.tag == "!Binary" {
                    let value = match t.value {
                        Value::String(s) => s,
                        _ => {
                            return Err(ReencodeError::InvalidFormat(
                                "binary data is not a string".to_string(),
                            ))
                        }
                    };
                    let value = (0..value.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&value[i..i + 2], 16))
                        .collect::<Result<Vec<u8>, ParseIntError>>()
                        .map_err(|e| ReencodeError::InvalidFormat(e.to_string()))?;
                    UnknownValue::LengthDelimited(value)
                } else {
                    log::info!("Unexpected YAML tag {}, discarding.", t.tag);
                    return Self::add_field(message, field_num, t.value);
                }
            }
            Value::Bool(b) => UnknownValue::Varint(b as u64),
            Value::Number(n) => {
                let field = message.descriptor_dyn().field_by_number(field_num);
                int_value(n, field.as_ref())
            }
            Value::String(s) => UnknownValue::LengthDelimited(s.into_bytes()),
            Value::Mapping(m) => {
                let mut descriptor = Empty::descriptor();
                if let Some(field) = message.descriptor_dyn().field_by_number(field_num) {
                    if let RuntimeFieldType::Singular(RuntimeType::Message(md)) =
                        field.runtime_field_type()
                    {
                        descriptor = md;
                    } else if let RuntimeFieldType::Map(k, v) = field.runtime_field_type() {
                        // TODO: handle maps.
                    }
                }
                let child_message = descriptor.new_instance();
                let val = Self::merge_yaml_into_message(Value::Mapping(m), child_message)?;
                UnknownValue::LengthDelimited(val)
            }
        };
        message.mut_unknown_fields_dyn().add_value(field_num, value);
        Ok(())
    }

    fn primitive_type_to_yaml(x: ReflectValueRef, field_type: Type) -> Value {
        match x {
            ReflectValueRef::U32(x) => tag_number(Value::Number(Number::from(x)), field_type),
            ReflectValueRef::U64(x) => tag_number(Value::Number(Number::from(x)), field_type),
            ReflectValueRef::I32(x) => Value::Number(Number::from(x)),
            ReflectValueRef::I64(x) => Value::Number(Number::from(x)),
            ReflectValueRef::F32(x) => Value::Number(Number::from(x)),
            ReflectValueRef::F64(x) => Value::Number(Number::from(x)),
            ReflectValueRef::Bool(x) => Value::from(x),
            ReflectValueRef::String(x) => Value::from(x),
            ReflectValueRef::Bytes(x) => Value::Tagged(Box::new(TaggedValue {
                tag: Tag::new("Binary"),
                value: Value::String(Self::bytes_to_hex_string(x)),
            })),
            ReflectValueRef::Enum(descriptor, i) => descriptor
                .value_by_number(i)
                .map(|v| Value::String(v.name().to_string()))
                .unwrap_or_else(|| Value::Number(Number::from(i))),
            ReflectValueRef::Message(m) => Self::message_to_yaml(m.deref()),
        }
    }
    pub(crate) fn message_to_yaml(message: &dyn MessageDyn) -> Value {
        let mut ret = Mapping::new();

        for field in message.descriptor_dyn().fields() {
            let key = if field.name().is_empty() {
                Value::from(field.number())
            } else {
                Value::from(field.name())
            };
            let field_type = field
                .proto()
                .type_
                .map(|t| t.enum_value_or(TYPE_BYTES))
                .unwrap_or(TYPE_BYTES);

            let value = match field.get_reflect(message) {
                ReflectFieldRef::Optional(x) => {
                    if let Some(x) = x.value() {
                        Self::primitive_type_to_yaml(x, field_type)
                    } else {
                        Value::Null
                    }
                }
                ReflectFieldRef::Repeated(x) => Value::Sequence(
                    x.into_iter()
                        .map(|x| Self::primitive_type_to_yaml(x, field_type))
                        .collect(),
                ),
                ReflectFieldRef::Map(x) => Value::Mapping(
                    x.into_iter()
                        .map(|(k, v)| {
                            (
                                Self::primitive_type_to_yaml(k, field_type),
                                Self::primitive_type_to_yaml(v, field_type),
                            )
                        })
                        .collect(),
                ),
            };
            ret.insert(key, value);
        }
        Value::Mapping(ret)
    }

    fn create_descriptor(
        data: &[u8],
        existing: MessageDescriptor,
    ) -> Result<MessageDescriptor, PrettifyError> {
        let proto = Self::create_descriptor_proto(data, existing, "Unknown".to_string())?;

        let descriptor = {
            let mut proto_file = FileDescriptorProto::new();
            proto_file.message_type.push(proto);

            FileDescriptor::new_dynamic(proto_file, &[])
                // FIXME
                .unwrap()
                .messages()
                .next()
                .unwrap()
        };

        Ok(descriptor)
    }

    fn create_descriptor_proto(
        data: &[u8],
        existing: MessageDescriptor,
        name: String,
    ) -> Result<DescriptorProto, PrettifyError> {
        let message = existing
            .parse_from_bytes(data)
            .map_err(|e| PrettifyError::Generic(format!("failed to parse protobuf: {e}")))?;

        let mut descriptor = existing.proto().clone();

        let mut field_groups: BTreeMap<u32, Vec<UnknownValueRef>> = BTreeMap::new();
        for (field_number, value) in message.unknown_fields_dyn().iter() {
            field_groups.entry(field_number).or_default().push(value);
        }

        for (field_index, field_values) in field_groups.into_iter() {
            let mut add_int = |typ: Type| {
                descriptor.field.push(FieldDescriptorProto {
                    number: Some(field_index as i32),
                    type_: Some(EnumOrUnknown::from(typ)),
                    ..Default::default()
                });
            };
            match field_values[0] {
                // We can't use float/double here because of NaN handling.
                UnknownValueRef::Fixed32(_) => add_int(TYPE_FIXED32),
                UnknownValueRef::Fixed64(_) => add_int(TYPE_FIXED64),
                UnknownValueRef::Varint(_) => add_int(TYPE_UINT64),
                UnknownValueRef::LengthDelimited(data) => {
                    let field_values = field_values
                        .iter()
                        .map(|x| match x {
                            UnknownValueRef::LengthDelimited(data) => Ok(*data),
                            _ => Err(PrettifyError::Generic(
                                "varying types in protobuf".to_string(),
                            )),
                        })
                        .collect::<Result<Vec<&[u8]>, PrettifyError>>()?;

                    match Self::guess_field_type(&field_values, &name, field_index) {
                        GuessedFieldType::String => add_int(TYPE_STRING),
                        GuessedFieldType::Unknown => add_int(TYPE_BYTES),
                        GuessedFieldType::Message(m) => {
                            descriptor.field.push(FieldDescriptorProto {
                                number: Some(field_index as i32),
                                type_name: Some(format!(".{}.{}", name, m.name())),
                                type_: Some(EnumOrUnknown::from(Type::TYPE_MESSAGE)),
                                ..Default::default()
                            });
                            descriptor.nested_type.push(*m);
                        }
                    }
                }
            }
            if field_values.len() > 1 {
                descriptor
                    .field
                    .last_mut()
                    .expect("we just added this field")
                    .set_label(LABEL_REPEATED);
            }
        }

        descriptor.set_name(name);
        Ok(descriptor)
    }

    fn guess_field_type(values: &[&[u8]], name: &str, field_index: u32) -> GuessedFieldType {
        if values.iter().all(|data| {
            std::str::from_utf8(data).is_ok_and(|s| {
                s.chars()
                    .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            })
        }) {
            return GuessedFieldType::String;
        }

        // Try to parse as a nested message
        let name = format!("{name}.unknown_field_{field_index}");
        if let Ok(mut descriptor) =
            { Self::create_descriptor_proto(values[0], Empty::descriptor(), name) }
        {
            if values
                .iter()
                .skip(1)
                .all(|data| descriptor.descriptor_dyn().parse_from_bytes(data).is_ok())
            {
                descriptor.set_name(format!("unknown_field_{field_index}"));
                return GuessedFieldType::Message(Box::new(descriptor));
            }
        }

        GuessedFieldType::Unknown
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const VARINT_PROTO: &[u8] = &[0x08, 0x96, 0x01];
    const VARINT_YAML: &str = "1: 150";
    const VARINT_NEG_PROTO: &[u8] = &[0x08, 0x0B];
    const VARINT_NEG_YAML: &str = "1: 11 # signed: -6\n";
    const REPEATED_NUMERIC_PROTO: &[u8] = &[0x08, 0x01, 0x08, 0x02, 0x08, 0x03];
    const REPEATED_NUMERIC_YAML: &str = "1:\n- 1 # signed: -1\n- 2\n- 3 # signed: -2\n";
    const REPEATED_PACKED_PROTO: &[u8] = &[0x32, 0x06, 0x03, 0x8E, 0x02, 0x9E, 0xA7, 0x05];
    const REPEATED_PACKED_YAML: &str = "6: !Binary 038e029ea705\n";
    const FIXED32_PROTO: &[u8] = &[0x15, 0x00, 0x00, 0x80, 0xBF];
    const FIXED32_YAML: &str = "2: 3212836864 # float: -1, i32: -1082130432\n";
    const STRING_PROTO: &[u8] = &[0x22, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F];
    const STRING_YAML: &str = "4: hello\n";
    const NESTED_MESSAGE_PROTO: &[u8] = &[0x2A, 0x02, 0x08, 0x2A];
    const NESTED_MESSAGE_YAML: &str = "5:\n  1: 42\n";

    mod reencode {
        use super::*;

        #[test]
        fn test_varint() {
            let result = Protobuf.reencode(VARINT_YAML, VARINT_PROTO).unwrap();
            assert_eq!(result, VARINT_PROTO);
        }

        #[test]
        fn test_varint_signed() {
            let result = Protobuf
                .reencode(VARINT_NEG_YAML, VARINT_NEG_PROTO)
                .unwrap();
            assert_eq!(result, VARINT_NEG_PROTO);
        }

        #[test]
        fn test_repeated_numeric() {
            let result = Protobuf
                .reencode(REPEATED_NUMERIC_YAML, REPEATED_NUMERIC_PROTO)
                .unwrap();
            assert_eq!(result, REPEATED_NUMERIC_PROTO);
        }

        #[test]
        fn test_packed_repeated() {
            let result = Protobuf
                .reencode(REPEATED_PACKED_YAML, REPEATED_PACKED_PROTO)
                .unwrap();
            assert_eq!(result, REPEATED_PACKED_PROTO);
        }

        // Fixed32 tests
        #[test]
        fn test_fixed32() {
            let result = Protobuf.reencode(FIXED32_YAML, FIXED32_PROTO).unwrap();
            assert_eq!(result, FIXED32_PROTO);
        }

        // String field test
        #[test]
        fn test_string_field() {
            let result = Protobuf.reencode(STRING_YAML, STRING_PROTO).unwrap();
            assert_eq!(result, STRING_PROTO);
        }

        #[test]
        fn test_nested_message() {
            let result = Protobuf
                .reencode(NESTED_MESSAGE_YAML, NESTED_MESSAGE_PROTO)
                .unwrap();
            assert_eq!(result, NESTED_MESSAGE_PROTO);
        }

        #[test]
        fn test_new_nested_message() {
            let result = Protobuf
                .reencode(NESTED_MESSAGE_YAML, FIXED32_PROTO)
                .unwrap();
            assert_eq!(result, NESTED_MESSAGE_PROTO);
        }

        #[test]
        fn test_new_string() {
            let result = Protobuf.reencode(STRING_YAML, FIXED32_PROTO).unwrap();
            assert_eq!(result, STRING_PROTO);
        }
    }

    mod prettify {
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
        fn test_nested_twice() {
            const PROTO: &[u8] = &[0x2A, 0x04, 0x2A, 0x02, 0x08, 0x2A];
            let result = Protobuf.prettify(PROTO.to_vec()).unwrap();
            assert_eq!(result, "5:\n  5:\n    1: 42\n");
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
}
