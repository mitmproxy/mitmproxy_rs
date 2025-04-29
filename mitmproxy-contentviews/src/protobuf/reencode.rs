use crate::protobuf::view_protobuf::tags;
use anyhow::{bail, Context};
use protobuf::descriptor::field_descriptor_proto::Type;
use protobuf::descriptor::field_descriptor_proto::Type::{TYPE_FIXED32, TYPE_FIXED64};
use protobuf::reflect::{FieldDescriptor, MessageDescriptor, RuntimeFieldType, RuntimeType};
use protobuf::well_known_types::empty::Empty;
use protobuf::{MessageDyn, MessageFull, UnknownValue};
use serde_yaml::{Number, Value};
use std::num::ParseIntError;
use std::str::FromStr;

pub(super) fn reencode_yaml(
    value: Value,
    descriptor: &MessageDescriptor,
) -> anyhow::Result<Vec<u8>> {
    let message = descriptor.new_instance();
    merge_yaml_into_message(value, message)
}

fn merge_yaml_into_message(
    value: Value,
    mut message: Box<dyn MessageDyn>,
) -> anyhow::Result<Vec<u8>> {
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

fn add_field(message: &mut dyn MessageDyn, field_num: u32, value: Value) -> anyhow::Result<()> {
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
                    .collect::<anyhow::Result<Vec<u8>, ParseIntError>>()
                    .context("Invalid hex string")?;
                UnknownValue::LengthDelimited(value)
            } else if t.tag == *tags::FIXED32 {
                let Value::Number(n) = t.value else {
                    bail!("!fixed32 is not a number");
                };
                let value = n
                    .as_u64()
                    .map(|n| n as u32)
                    .or_else(|| n.as_i64().map(|s| s as u32))
                    .or_else(|| n.as_f64().map(|f| (f as f32).to_bits()))
                    .context("Failed to convert !fixed32 value to a valid number")?;
                UnknownValue::Fixed32(value)
            } else if t.tag == *tags::FIXED64 {
                let Value::Number(n) = t.value else {
                    bail!("!fixed64 is not a number");
                };
                let value = n
                    .as_u64()
                    .or_else(|| n.as_i64().map(|s| s as u64))
                    .or_else(|| n.as_f64().map(|f| f.to_bits()))
                    .context("Failed to convert !fixed64 value to a valid number")?;
                UnknownValue::Fixed64(value)
            } else if t.tag == *tags::ZIGZAG {
                let Value::Number(n) = t.value else {
                    bail!("!sint is not a number");
                };
                let Some(n) = n.as_i64() else {
                    bail!("!sint is not an integer");
                };
                UnknownValue::Varint(encode_zigzag64(n))
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

// Zigzag-encode a 64-bit integer
fn encode_zigzag64(n: i64) -> u64 {
    ((n << 1) ^ (n >> 63)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_zigzag64() {
        assert_eq!(encode_zigzag64(0), 0);
        assert_eq!(encode_zigzag64(-1), 1);
        assert_eq!(encode_zigzag64(1), 2);
        assert_eq!(encode_zigzag64(-2), 3);
        assert_eq!(encode_zigzag64(0x7fffffff), 0xfffffffe);
        assert_eq!(encode_zigzag64(-0x80000000), 0xffffffff);
    }
}
