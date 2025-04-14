use crate::protobuf::existing_proto_definitions::DescriptorWithDeps;
use anyhow::Context;
use protobuf::descriptor::field_descriptor_proto::Label::LABEL_REPEATED;
use protobuf::descriptor::field_descriptor_proto::Type;
use protobuf::descriptor::field_descriptor_proto::Type::{
    TYPE_BYTES, TYPE_FIXED32, TYPE_FIXED64, TYPE_STRING, TYPE_UINT64,
};
use protobuf::descriptor::{DescriptorProto, FieldDescriptorProto, FileDescriptorProto};
use protobuf::reflect::{FileDescriptor, MessageDescriptor};
use protobuf::{EnumOrUnknown, MessageDyn, UnknownValueRef};
/// Existing protobuf definition + raw data => merged protobuf definition
use std::collections::BTreeMap;

enum GuessedFieldType {
    String,
    Message(Box<DescriptorProto>),
    Unknown,
}

/// Create a "merged" MessageDescriptor. Mostly a wrapper around `create_descriptor_proto`.
pub(super) fn merge_proto_and_descriptor(
    data: &[u8],
    desc: &DescriptorWithDeps,
) -> anyhow::Result<MessageDescriptor> {
    let new_proto = create_descriptor_proto(data, &desc.descriptor)?;

    let descriptor = {
        let mut file_descriptor_proto = desc.descriptor.file_descriptor_proto().clone();

        let message_idx = file_descriptor_proto
            .message_type
            .iter()
            .enumerate()
            .filter_map(|(i, d)| (d.name() == desc.descriptor.name_to_package()).then_some(i))
            .next()
            .context("failed to find existing message descriptor index")?;
        file_descriptor_proto.message_type[message_idx] = new_proto;

        /*
        XXX: Skipping this as it doesn't seem to bring any immediate benefits.
        let dependencies = dependencies
            .iter()
            .cloned()
            .filter(|d| d != existing.file_descriptor())
            .collect::<Vec<_>>();
         */

        FileDescriptor::new_dynamic(file_descriptor_proto, &desc.dependencies)
            .context("failed to create new dynamic file descriptor")?
            .message_by_package_relative_name(desc.descriptor.name_to_package())
            .with_context(|| {
                format!(
                    "did not find {} in descriptor",
                    desc.descriptor.name_to_package()
                )
            })?
    };

    Ok(descriptor)
}

/// Create a new (empty) MessageDescriptor for the given package and name.
pub(super) fn new_empty_descriptor(package: Option<String>, name: &str) -> MessageDescriptor {
    // Create nested descriptor protos. For example, if the name is OuterMessage.InnerMessage,
    // we create a descriptor for InnerMessage and set it as a nested type of OuterMessage.
    // This is a bit of a hack, but the best way to get type_name right.
    let mut parts = name.rsplit(".");
    let mut head = {
        let mut descriptor = DescriptorProto::new();
        descriptor.set_name(parts.next().unwrap().to_string());
        descriptor
    };
    for p in parts {
        let mut descriptor = DescriptorProto::new();
        descriptor.set_name(p.to_string());
        descriptor.nested_type.push(head);
        head = descriptor;
    }

    let file_descriptor_proto = {
        let mut fd = FileDescriptorProto::new();
        fd.package = package;
        fd.message_type.push(head);
        fd
    };
    FileDescriptor::new_dynamic(file_descriptor_proto, &[])
        .unwrap()
        .message_by_package_relative_name(name)
        .unwrap()
}

/// Create a DescriptorProto that combines the `existing` MessageDescriptor with (guessed)
/// metadata for all unknown fields in the protobuf `data`.
fn create_descriptor_proto(
    data: &[u8],
    existing: &MessageDescriptor,
) -> anyhow::Result<DescriptorProto> {
    let message = existing
        .parse_from_bytes(data)
        .with_context(|| format!("failed to parse protobuf: {}", existing.full_name()))?;

    let mut descriptor = existing.proto().clone();

    let mut field_groups: BTreeMap<u32, Vec<UnknownValueRef>> = BTreeMap::new();
    for (field_number, value) in message.unknown_fields_dyn().iter() {
        field_groups.entry(field_number).or_default().push(value);
    }

    for (field_index, field_values) in field_groups.into_iter() {
        let name = Some(format!("unknown_field_{}", field_index));
        let mut add_int = |name: Option<String>, typ: Type| {
            descriptor.field.push(FieldDescriptorProto {
                number: Some(field_index as i32),
                name,
                type_: Some(EnumOrUnknown::from(typ)),
                ..Default::default()
            });
        };
        match field_values[0] {
            // We can't use float/double here because of NaN handling.
            UnknownValueRef::Fixed32(_) => add_int(name, TYPE_FIXED32),
            UnknownValueRef::Fixed64(_) => add_int(name, TYPE_FIXED64),
            UnknownValueRef::Varint(_) => add_int(name, TYPE_UINT64),
            UnknownValueRef::LengthDelimited(_) => {
                let field_values = field_values
                    .iter()
                    .map(|x| match x {
                        UnknownValueRef::LengthDelimited(data) => Ok(*data),
                        _ => Err(anyhow::anyhow!("varying types in protobuf")),
                    })
                    .collect::<anyhow::Result<Vec<&[u8]>>>()?;

                match guess_field_type(existing, field_index, &field_values) {
                    GuessedFieldType::String => add_int(name, TYPE_STRING),
                    GuessedFieldType::Unknown => add_int(name, TYPE_BYTES),
                    GuessedFieldType::Message(m) => {
                        descriptor.field.push(FieldDescriptorProto {
                            name,
                            number: Some(field_index as i32),
                            type_name: Some(format!(".{}.{}", existing.full_name(), m.name())),
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

    Ok(descriptor)
}

/// Given all `values` of a field, guess its type.
fn guess_field_type(
    parent: &MessageDescriptor,
    field_index: u32,
    values: &[&[u8]],
) -> GuessedFieldType {
    if values.iter().all(|data| {
        std::str::from_utf8(data).is_ok_and(|s| {
            s.chars()
                .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        })
    }) {
        return GuessedFieldType::String;
    }

    // Try to parse as a nested message
    let existing = new_empty_descriptor(
        parent.file_descriptor_proto().package.clone(),
        &format!("{}.UnknownField{}", parent.name_to_package(), field_index),
    );
    if let Ok(descriptor) = create_descriptor_proto(values[0], &existing) {
        if values
            .iter()
            .skip(1)
            .all(|data| descriptor.descriptor_dyn().parse_from_bytes(data).is_ok())
        {
            return GuessedFieldType::Message(Box::new(descriptor));
        }
    }

    GuessedFieldType::Unknown
}
