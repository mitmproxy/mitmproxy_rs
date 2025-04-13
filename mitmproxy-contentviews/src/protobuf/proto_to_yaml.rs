/// Parsed protobuf message => YAML value
use protobuf::descriptor::field_descriptor_proto::Type;
use protobuf::descriptor::field_descriptor_proto::Type::{
    TYPE_BYTES, TYPE_FIXED32, TYPE_FIXED64, TYPE_UINT64,
};
use protobuf::reflect::{ReflectFieldRef, ReflectValueRef};
use protobuf::MessageDyn;
use serde_yaml::value::TaggedValue;
use serde_yaml::{Mapping, Number, Value};
use std::fmt::Write;
use std::ops::Deref;

pub(crate) fn message_to_yaml(message: &dyn MessageDyn) -> Value {
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
                    continue;
                }
            }
            ReflectFieldRef::Repeated(x) => {
                if x.is_empty() {
                    continue;
                }
                Value::Sequence(
                    x.into_iter()
                        .map(|x| primitive_type_to_yaml(x, field_type))
                        .collect(),
                )
            }
            ReflectFieldRef::Map(x) => {
                if x.is_empty() {
                    continue;
                }
                Value::Mapping(
                    x.into_iter()
                        .map(|(k, v)| {
                            (
                                primitive_type_to_yaml(k, field_type),
                                primitive_type_to_yaml(v, field_type),
                            )
                        })
                        .collect(),
                )
            }
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
            tag: crate::protobuf::view_protobuf::tags::BINARY.clone(),
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
            tag: crate::protobuf::view_protobuf::tags::VARINT.clone(),
            value,
        })),
        TYPE_FIXED64 => Value::Tagged(Box::new(TaggedValue {
            tag: crate::protobuf::view_protobuf::tags::FIXED64.clone(),
            value,
        })),
        TYPE_FIXED32 => Value::Tagged(Box::new(TaggedValue {
            tag: crate::protobuf::view_protobuf::tags::FIXED32.clone(),
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
