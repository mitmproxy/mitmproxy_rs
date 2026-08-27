use crate::protobuf::raw_to_proto::{self, GuessedFieldType, guess_varlen_type};
use crate::protobuf::view_protobuf::tags;
use anyhow::Context;
/// Parsed protobuf message => YAML value
use protobuf::descriptor::field_descriptor_proto::Type;
use protobuf::descriptor::field_descriptor_proto::Type::{TYPE_FIXED32, TYPE_FIXED64, TYPE_UINT64};
use protobuf::reflect::{MessageDescriptor, ReflectFieldRef, ReflectValueRef};
use protobuf::{MessageDyn, UnknownValueRef};
use serde_yaml::value::TaggedValue;
use serde_yaml::{Number, Value};
use std::collections::BTreeMap;
use std::ops::Deref;

pub(super) fn decode_proto_to_yaml(
    data: &[u8],
    descriptor: &MessageDescriptor,
) -> anyhow::Result<Value> {
    let message = descriptor
        .parse_from_bytes(data)
        .context("failed to parse protobuf")?;
    Ok(message_to_yaml_value(message.as_ref()))
}

/// Convert a protobuf message to a YAML [`Value::Mapping`].
///
/// Handles known and unknown fields and sorts them by field number.
/// For unknown bytes-values, will attempt to guess whether they're strings,
/// messages, or bytes.
fn message_to_yaml_value(message: &dyn MessageDyn) -> Value {
    // (field_number, key, value)
    let mut all_field_values: Vec<(i32, Value, Value)> = Vec::new();

    // Go through the known fields
    for field in message.descriptor_dyn().fields() {
        let value = match field.get_reflect(message) {
            ReflectFieldRef::Optional(x) => {
                if let Some(x) = x.value() {
                    value_to_yaml(x)
                } else {
                    continue;
                }
            }
            ReflectFieldRef::Repeated(x) => {
                if x.is_empty() {
                    continue;
                }
                Value::Sequence(x.into_iter().map(|x| value_to_yaml(x)).collect())
            }
            ReflectFieldRef::Map(x) => {
                if x.is_empty() {
                    continue;
                }
                Value::Mapping(
                    x.into_iter()
                        .map(|(k, v)| (value_to_yaml(k), value_to_yaml(v)))
                        .collect(),
                )
            }
        };

        all_field_values.push((field.number(), Value::from(field.name()), value));
    }

    // Group the unknown values by field number
    let mut unknown_field_groups: BTreeMap<i32, Vec<UnknownValueRef>> = BTreeMap::new();
    for (field_number, value) in message.unknown_fields_dyn().iter() {
        unknown_field_groups
            .entry(field_number as i32)
            .or_default()
            .push(value);
    }

    for (field_number, unknown_values) in unknown_field_groups.into_iter() {
        // With the fields grouped, see if we should expect just numbers, or bytes which we need to guess the type of
        let varlen_count = unknown_values
            .iter()
            .filter(|v| matches!(v, UnknownValueRef::LengthDelimited(_)))
            .count();

        let values: Vec<Value> = if varlen_count == 0 || varlen_count != unknown_values.len() {
            // We have only numbers (or bad protobuf with mixed types)
            unknown_values
                .into_iter()
                .map(|v| match v {
                    UnknownValueRef::Fixed32(num) => tag_number(Number::from(num), TYPE_FIXED32),
                    UnknownValueRef::Fixed64(num) => tag_number(Number::from(num), TYPE_FIXED64),
                    UnknownValueRef::Varint(num) => tag_number(Number::from(num), TYPE_UINT64),
                    UnknownValueRef::LengthDelimited(data) => {
                        // There *shouldn't* be mixed types, but since we can deal with this edge case, let's.
                        // We're running the probe per item, but again, that'll do.
                        match guess_varlen_type(&[data]) {
                            GuessedFieldType::String(strings) => {
                                strings.into_iter().map(Value::String).next()
                            }
                            GuessedFieldType::Unknown => Some(
                                // Let's take advantage of value_to_yaml()
                                value_to_yaml(ReflectValueRef::Bytes(data)),
                            ),
                            GuessedFieldType::Message(messages) => messages
                                .into_iter()
                                .map(|m| message_to_yaml_value(m.deref()))
                                .next(),
                        }
                        .expect("guess_varlen_type() provided us with no values")
                    }
                })
                .collect()
        } else {
            // Collect the bytes and try to guess what they represent together
            let varlen_bytes: Vec<&[u8]> = unknown_values
                .into_iter()
                .map(|v| match v {
                    UnknownValueRef::LengthDelimited(data) => data,
                    _ => unreachable!("already checked; there should be bytes only"),
                })
                .collect();

            match raw_to_proto::guess_varlen_type(&varlen_bytes) {
                GuessedFieldType::String(strings) => {
                    strings.into_iter().map(Value::String).collect()
                }
                GuessedFieldType::Unknown => varlen_bytes
                    .into_iter()
                    .map(|data| {
                        // Let's take advantage of value_to_yaml()
                        value_to_yaml(ReflectValueRef::Bytes(data))
                    })
                    .collect(),
                GuessedFieldType::Message(messages) => messages
                    .into_iter()
                    .map(|m| message_to_yaml_value(m.deref()))
                    .collect(),
            }
        };

        // Move out the only Value, or wrap the vector in a YAML Sequence
        let value = match values {
            v if v.len() == 1 => v.into_iter().next().unwrap(),
            v => Value::Sequence(v),
        };
        all_field_values.push((field_number, Value::from(field_number), value));
    }

    // Sort the fields by the field number and collect our Mapping
    all_field_values.sort_by_key(|t| t.0);

    Value::Mapping(all_field_values.into_iter().map(|t| (t.1, t.2)).collect())
}

/// Convert `x` into a [`Value`]
fn value_to_yaml(x: ReflectValueRef) -> Value {
    match x {
        ReflectValueRef::U32(x) => Value::Number(Number::from(x)),
        ReflectValueRef::U64(x) => Value::Number(Number::from(x)),
        ReflectValueRef::I32(x) => Value::Number(Number::from(x)),
        ReflectValueRef::I64(x) => Value::Number(Number::from(x)),
        ReflectValueRef::F32(x) => Value::Number(Number::from(x)),
        ReflectValueRef::F64(x) => Value::Number(Number::from(x)),
        ReflectValueRef::Bool(x) => Value::from(x),
        ReflectValueRef::String(x) => Value::from(x),
        ReflectValueRef::Bytes(x) => Value::Tagged(Box::new(TaggedValue {
            tag: tags::BINARY.clone(),
            value: Value::String(data_encoding::HEXLOWER.encode(x)),
        })),
        ReflectValueRef::Enum(descriptor, i) => descriptor
            .value_by_number(i)
            .map(|v| Value::String(v.name().to_string()))
            .unwrap_or_else(|| Value::Number(Number::from(i))),
        ReflectValueRef::Message(m) => message_to_yaml_value(m.deref()),
    }
}

/// Tag a [`Number`] for YAML given a hint type
fn tag_number(number: Number, tag_type: Type) -> Value {
    let tag = match tag_type {
        TYPE_UINT64 => Some(tags::VARINT.clone()),
        TYPE_FIXED64 => Some(tags::FIXED64.clone()),
        TYPE_FIXED32 => Some(tags::FIXED32.clone()),
        _ => None,
    };

    match tag {
        Some(tag) => Value::Tagged(Box::new(TaggedValue {
            tag,
            value: Value::Number(number),
        })),
        None => Value::Number(number),
    }
}
