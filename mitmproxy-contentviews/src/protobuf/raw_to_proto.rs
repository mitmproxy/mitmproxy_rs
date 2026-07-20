use protobuf::MessageDyn;
use protobuf::descriptor::{DescriptorProto, FileDescriptorProto};
use protobuf::reflect::{FileDescriptor, MessageDescriptor};
/// Existing protobuf definition + raw data => merged protobuf definition
use std::str;

pub(crate) enum GuessedFieldType {
    String(Vec<String>),
    Message(Vec<Box<dyn MessageDyn>>),
    Unknown,
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

/// Given a set of protobuf varlen field values, try to figure out the best type to display them.
///
/// In the case of [`GuessedFieldType::String`] and [`GuessedFieldType::Message`],
/// the decoded values are included.
pub(crate) fn guess_varlen_type(values: &[&[u8]]) -> GuessedFieldType {
    // Try to decode as printable strings
    let strings: Option<Vec<String>> = values
        .iter()
        .map(|data| {
            str::from_utf8(data).ok().and_then(|s| {
                s.chars()
                    // Check that the string is printable
                    .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                    .then(|| s.to_string())
            })
        })
        .collect();

    if let Some(strings) = strings {
        return GuessedFieldType::String(strings);
    }

    // Try to decode protobuf with an empty message type (all unknowns!)
    let descriptor = new_empty_descriptor(None, "Unknown");
    let messages: Option<Vec<_>> = values
        .iter()
        .map(|data| descriptor.parse_from_bytes(data).ok())
        .collect();

    if let Some(messages) = messages {
        return GuessedFieldType::Message(messages);
    }

    // Fall back to unrecognized bytestrings
    GuessedFieldType::Unknown
}
