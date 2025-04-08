use crate::{Metadata, Prettify, Reencode};
use anyhow::{bail, Context, Result};
use mitmproxy_highlight::Language;
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
use protobuf::{EnumOrUnknown, MessageDyn, MessageFull, UnknownValue};
use regex::Captures;
use serde_yaml::value::TaggedValue;
use serde_yaml::{Mapping, Number, Value};
use std::collections::BTreeMap;
use std::fmt::Write;
use std::num::ParseIntError;
use std::ops::Deref;
use std::str::FromStr;

mod tags {
    use regex::Regex;
    use serde_yaml::value::Tag;
    use std::sync::LazyLock;

    pub(super) static BINARY: LazyLock<Tag> = LazyLock::new(|| Tag::new("binary"));
    pub(super) static VARINT: LazyLock<Tag> = LazyLock::new(|| Tag::new("varint"));
    pub(super) static FIXED32: LazyLock<Tag> = LazyLock::new(|| Tag::new("fixed32"));
    pub(super) static FIXED64: LazyLock<Tag> = LazyLock::new(|| Tag::new("fixed64"));

    pub(super) static VARINT_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(&format!(r"{} (\d+)", *VARINT)).unwrap());
    pub(super) static FIXED32_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(&format!(r"{} (\d+)", *FIXED32)).unwrap());
    pub(super) static FIXED64_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(&format!(r"{} (\d+)", *FIXED64)).unwrap());
}

pub struct Protobuf;

enum GuessedFieldType {
    String,
    Message(Box<DescriptorProto>),
    Unknown,
}

impl Prettify for Protobuf {
    fn name(&self) -> &str {
        "Protobuf"
    }

    fn syntax_highlight(&self) -> Language {
        Language::Yaml
    }

    fn prettify(&self, data: &[u8], _metadata: &dyn Metadata) -> Result<String> {
        // Check if data is empty first
        if data.is_empty() {
            return Ok("{}  # empty protobuf message".to_string());
        }

        let existing = Empty::descriptor();
        let descriptor = raw_to_proto::merge_proto_and_descriptor(data, existing)?;

        // Parse protobuf and convert to YAML
        let message = descriptor
            .parse_from_bytes(data)
            .context("Error parsing protobuf")?;
        let yaml_value = proto_to_yaml::message_to_yaml(message.as_ref());

        let yaml_str = serde_yaml::to_string(&yaml_value).context("Failed to convert to YAML")?;
        yaml_to_pretty::apply_replacements(&yaml_str)
    }

    fn render_priority(&self, _data: &[u8], metadata: &dyn Metadata) -> f64 {
        match metadata.content_type() {
            Some("application/x-protobuf") => 1.0,
            Some("application/x-protobuffer") => 1.0,
            _ => 0.0,
        }
    }
}

impl Reencode for Protobuf {
    fn reencode(&self, data: &str, metadata: &dyn Metadata) -> Result<Vec<u8>> {
        let value: Value = serde_yaml::from_str(data).context("Invalid YAML")?;
        reencode::reencode_yaml(value, metadata)
    }
}

/// Existing protobuf definition + raw data => merged protobuf definition
mod raw_to_proto {
    use super::*;

    /// Create a "merged" MessageDescriptor. Mostly a wrapper around `create_descriptor_proto`.
    pub(super) fn merge_proto_and_descriptor(
        data: &[u8],
        existing: MessageDescriptor,
    ) -> anyhow::Result<MessageDescriptor> {
        let proto = create_descriptor_proto(data, existing, "Unknown".to_string())?;

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

    /// Create a DescriptorProto that combines the `existing` MessageDescriptor with (guessed)
    /// metadata for all unknown fields in the protobuf `data`.
    fn create_descriptor_proto(
        data: &[u8],
        existing: MessageDescriptor,
        name: String,
    ) -> Result<DescriptorProto> {
        let message = existing
            .parse_from_bytes(data)
            .context("failed to parse protobuf")?;

        let mut descriptor = existing.proto().clone();

        let mut field_groups: BTreeMap<u32, Vec<UnknownValueRef>> = BTreeMap::new();
        for (field_number, value) in message.unknown_fields_dyn().iter() {
            field_groups.entry(field_number).or_default().push(value);
        }

        for (field_index, field_values) in field_groups.into_iter() {
            let mut add_int = |typ: Type| {
                descriptor.field.push(FieldDescriptorProto {
                    number: Some(field_index as i32),
                    name: Some(format!("unknown_field_{}", field_index)),
                    type_: Some(EnumOrUnknown::from(typ)),
                    ..Default::default()
                });
            };
            match field_values[0] {
                // We can't use float/double here because of NaN handling.
                UnknownValueRef::Fixed32(_) => add_int(TYPE_FIXED32),
                UnknownValueRef::Fixed64(_) => add_int(TYPE_FIXED64),
                UnknownValueRef::Varint(_) => add_int(TYPE_UINT64),
                UnknownValueRef::LengthDelimited(_) => {
                    let field_values = field_values
                        .iter()
                        .map(|x| match x {
                            UnknownValueRef::LengthDelimited(data) => Ok(*data),
                            _ => Err(anyhow::anyhow!("varying types in protobuf")),
                        })
                        .collect::<anyhow::Result<Vec<&[u8]>>>()?;

                    match guess_field_type(&field_values, &name, field_index) {
                        GuessedFieldType::String => add_int(TYPE_STRING),
                        GuessedFieldType::Unknown => add_int(TYPE_BYTES),
                        GuessedFieldType::Message(m) => {
                            descriptor.field.push(FieldDescriptorProto {
                                number: Some(field_index as i32),
                                name: Some(format!("unknown_field_{}", field_index)),
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

    /// Given all `values` of a field, guess its type.
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
            { create_descriptor_proto(values[0], Empty::descriptor(), name) }
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
}

/// Parsed protobuf message => YAML value
mod proto_to_yaml {
    use super::*;

    pub(super) fn message_to_yaml(message: &dyn MessageDyn) -> Value {
        let mut ret = Mapping::new();

        for field in message.descriptor_dyn().fields() {
            let key = if field.name().starts_with("unknown_field_") {
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
                        primitive_type_to_yaml(x, field_type)
                    } else {
                        Value::Null
                    }
                }
                ReflectFieldRef::Repeated(x) => Value::Sequence(
                    x.into_iter()
                        .map(|x| primitive_type_to_yaml(x, field_type))
                        .collect(),
                ),
                ReflectFieldRef::Map(x) => Value::Mapping(
                    x.into_iter()
                        .map(|(k, v)| {
                            (
                                primitive_type_to_yaml(k, field_type),
                                primitive_type_to_yaml(v, field_type),
                            )
                        })
                        .collect(),
                ),
            };
            ret.insert(key, value);
        }
        Value::Mapping(ret)
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
                tag: tags::BINARY.clone(),
                value: Value::String(bytes_to_hex_string(x)),
            })),
            ReflectValueRef::Enum(descriptor, i) => descriptor
                .value_by_number(i)
                .map(|v| Value::String(v.name().to_string()))
                .unwrap_or_else(|| Value::Number(Number::from(i))),
            ReflectValueRef::Message(m) => message_to_yaml(m.deref()),
        }
    }

    fn tag_number(value: Value, field_type: Type) -> Value {
        match field_type {
            TYPE_UINT64 => Value::Tagged(Box::new(TaggedValue {
                tag: tags::VARINT.clone(),
                value,
            })),
            TYPE_FIXED64 => Value::Tagged(Box::new(TaggedValue {
                tag: tags::FIXED64.clone(),
                value,
            })),
            TYPE_FIXED32 => Value::Tagged(Box::new(TaggedValue {
                tag: tags::FIXED32.clone(),
                value,
            })),
            _ => value,
        }
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

/// YAML value => prettified text
mod yaml_to_pretty {
    use super::*;
    // Helper method to apply regex replacements to the YAML output
    pub(super) fn apply_replacements(yaml_str: &str) -> Result<String> {
        // Replace !fixed32 tags with comments showing float and i32 interpretations
        let with_fixed32 = tags::FIXED32_RE.replace_all(yaml_str, |caps: &Captures| {
            let value = caps[1].parse::<u32>().unwrap_or_default();
            let float_value = f32::from_bits(value);
            let i32_value = value as i32;

            if !float_value.is_nan() && float_value < 0.0 {
                format!(
                    "{} {} # float: {}, i32: {}",
                    *tags::FIXED32,
                    value,
                    float_value,
                    i32_value
                )
            } else if !float_value.is_nan() {
                format!("{} {} # float: {}", *tags::FIXED32, value, float_value)
            } else if i32_value < 0 {
                format!("{} {} # i32: {}", *tags::FIXED32, value, i32_value)
            } else {
                format!("{} {}", *tags::FIXED32, value)
            }
        });

        // Replace !fixed64 tags with comments showing double and i64 interpretations
        let with_fixed64 = tags::FIXED64_RE.replace_all(&with_fixed32, |caps: &Captures| {
            let value = caps[1].parse::<u64>().unwrap_or_default();
            let double_value = f64::from_bits(value);
            let i64_value = value as i64;

            if !double_value.is_nan() && double_value < 0.0 {
                format!(
                    "{} {} # double: {}, i64: {}",
                    *tags::FIXED64,
                    value,
                    double_value,
                    i64_value
                )
            } else if !double_value.is_nan() {
                format!("{} {} # double: {}", *tags::FIXED64, value, double_value)
            } else if i64_value < 0 {
                format!("{} {} # i64: {}", *tags::FIXED64, value, i64_value)
            } else {
                format!("{} {}", *tags::FIXED64, value)
            }
        });

        // Replace !varint tags with comments showing signed interpretation if different
        let with_varint = tags::VARINT_RE.replace_all(&with_fixed64, |caps: &Captures| {
            let unsigned_value = caps[1].parse::<u64>().unwrap_or_default();
            let i64_zigzag = decode_zigzag64(unsigned_value);

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
}

pub(super) mod reencode {
    use super::*;

    pub(crate) fn reencode_yaml(value: Value, _metadata: &dyn Metadata) -> Result<Vec<u8>> {
        let descriptor = Empty::descriptor();
        let message = descriptor.new_instance();
        merge_yaml_into_message(value, message)
    }

    fn merge_yaml_into_message(value: Value, mut message: Box<dyn MessageDyn>) -> Result<Vec<u8>> {
        let Value::Mapping(mapping) = value else {
            bail!("YAML is not a mapping");
        };

        for (key, value) in mapping.into_iter() {
            let field_num = match key {
                Value::String(key) => {
                    if let Some(field) = message.descriptor_dyn().field_by_name(&key) {
                        field.number()
                    } else if let Ok(field_num) = i32::from_str(&key) {
                        field_num
                    } else {
                        bail!("Unknown protobuf field key: {key}");
                    }
                }
                Value::Number(key) => {
                    let Some(field_num) = key.as_i64() else {
                        bail!("Invalid protobuf field number: {key}");
                    };
                    field_num as i32
                }
                other => {
                    bail!("Unexpected key: {other:?}");
                }
            } as u32;

            add_field(message.as_mut(), field_num, value)?;
        }

        message
            .write_to_bytes_dyn()
            .context("Failed to serialize protobuf")
    }

    fn add_field(message: &mut dyn MessageDyn, field_num: u32, value: Value) -> Result<()> {
        let value = match value {
            Value::Null => return Ok(()),
            Value::Sequence(seq) => {
                for s in seq.into_iter() {
                    add_field(message, field_num, s)?;
                }
                return Ok(());
            }
            Value::Tagged(t) => {
                // t.tag doesn't work for Match statements
                if t.tag == *tags::BINARY {
                    let value = match t.value {
                        Value::String(s) => s,
                        _ => bail!("Binary data is not a string"),
                    };
                    let value = (0..value.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&value[i..i + 2], 16))
                        .collect::<Result<Vec<u8>, ParseIntError>>()
                        .context("Invalid hex string")?;
                    UnknownValue::LengthDelimited(value)
                } else if t.tag == *tags::FIXED32 {
                    let value = match t.value {
                        Value::Number(s) if s.as_u64().is_some() => s.as_u64().unwrap(),
                        _ => bail!("Fixed32 data is not a u32"),
                    };
                    UnknownValue::Fixed32(value as u32)
                } else if t.tag == *tags::FIXED64 {
                    let value = match t.value {
                        Value::Number(s) if s.as_u64().is_some() => s.as_u64().unwrap(),
                        _ => bail!("Fixed64 data is not a u64"),
                    };
                    UnknownValue::Fixed64(value)
                } else {
                    log::info!("Unexpected YAML tag {}, discarding.", t.tag);
                    return add_field(message, field_num, t.value);
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
                    } else if let RuntimeFieldType::Map(_, _) = field.runtime_field_type() {
                        // TODO: handle maps.
                    }
                }
                let child_message = descriptor.new_instance();
                let val = merge_yaml_into_message(Value::Mapping(m), child_message)?;
                UnknownValue::LengthDelimited(val)
            }
        };
        message.mut_unknown_fields_dyn().add_value(field_num, value);
        Ok(())
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
