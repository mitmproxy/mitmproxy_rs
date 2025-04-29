use crate::protobuf::view_protobuf::tags;
/// Parsed protobuf message => YAML value
use protobuf::descriptor::field_descriptor_proto::Type;
use protobuf::descriptor::field_descriptor_proto::Type::{
    TYPE_BYTES, TYPE_FIXED32, TYPE_FIXED64, TYPE_UINT64,
};
use protobuf::reflect::{ReflectFieldRef, ReflectValueRef};
use protobuf::MessageDyn;
use serde_yaml::value::TaggedValue;
use serde_yaml::{Mapping, Number, Value};
use std::ops::Deref;

pub(super) fn message_to_yaml(message: &dyn MessageDyn) -> Value {
    let mut ret = Mapping::new();

    for field in message.descriptor_dyn().fields() {
        let is_unknown_field = field.name().starts_with("unknown_field_");
        let key = if is_unknown_field {
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
                    value_to_yaml(x, field_type, is_unknown_field)
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
                        .map(|x| value_to_yaml(x, field_type, is_unknown_field))
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
                                value_to_yaml(k, field_type, is_unknown_field),
                                value_to_yaml(v, field_type, is_unknown_field),
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

fn value_to_yaml(x: ReflectValueRef, field_type: Type, is_unknown: bool) -> Value {
    match x {
        ReflectValueRef::U32(x) => tag_number(Number::from(x), field_type, is_unknown),
        ReflectValueRef::U64(x) => tag_number(Number::from(x), field_type, is_unknown),
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
        ReflectValueRef::Message(m) => message_to_yaml(m.deref()),
    }
}

fn tag_number(number: Number, field_type: Type, is_unknown: bool) -> Value {
    if !is_unknown {
        return Value::Number(number);
    }
    match field_type {
        TYPE_UINT64 => Value::Tagged(Box::new(TaggedValue {
            tag: tags::VARINT.clone(),
            value: Value::Number(number),
        })),
        TYPE_FIXED64 => Value::Tagged(Box::new(TaggedValue {
            tag: tags::FIXED64.clone(),
            value: Value::Number(number),
        })),
        TYPE_FIXED32 => Value::Tagged(Box::new(TaggedValue {
            tag: tags::FIXED32.clone(),
            value: Value::Number(number),
        })),
        _ => Value::Number(number),
    }
}
