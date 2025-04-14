use crate::protobuf::raw_to_proto::new_empty_descriptor;
use crate::Metadata;
use anyhow::Context;
use protobuf::reflect::{FileDescriptor, MessageDescriptor};
use protobuf_parse::Parser;
use std::path::Path;

pub(super) struct DescriptorWithDeps {
    pub descriptor: MessageDescriptor,
    pub dependencies: Vec<FileDescriptor>,
}

impl Default for DescriptorWithDeps {
    fn default() -> Self {
        Self {
            descriptor: new_empty_descriptor(None, "Unknown"),
            dependencies: vec![],
        }
    }
}

pub(super) fn find_best_match(
    metadata: &dyn Metadata,
) -> anyhow::Result<Option<DescriptorWithDeps>> {
    // Parse existing protobuf definitions if available
    let Some(file_descriptors) = metadata
        .protobuf_definitions()
        .map(parse_file_descriptor_set)
        .transpose()
        .context("failed to parse proto file(s)")?
    else {
        return Ok(None);
    };

    // Find MessageDescriptor for the RPC.
    let rpc_info = RpcInfo::from_metadata(metadata);
    let Some(descriptor) =
        find_best_message(&file_descriptors, rpc_info, metadata.is_http_request())
    else {
        return Ok(None);
    };

    Ok(Some(DescriptorWithDeps {
        descriptor,
        dependencies: file_descriptors,
    }))
}

fn find_best_message(
    fds: &[FileDescriptor],
    rpc: Option<RpcInfo>,
    is_request: bool,
) -> Option<MessageDescriptor> {
    if let Some(rpc) = rpc {
        for file in fds {
            if file.proto().package() != rpc.package {
                continue;
            }
            for service in file.services() {
                if service.proto().name() != rpc.service {
                    continue;
                }
                for method in service.methods() {
                    if method.proto().name() != rpc.method {
                        continue;
                    }

                    return Some(if is_request {
                        method.input_type()
                    } else {
                        method.output_type()
                    });
                }
                log::info!(
                    "Found service {} in {}, but no method '{}'.",
                    rpc.service,
                    file.name(),
                    rpc.method
                );
            }
        }
        log::info!("Did not find {rpc} in protobuf definitions.");
    }

    let file = fds.first()?;
    if let Some(service) = file.services().next() {
        if let Some(method) = service.methods().next() {
            log::info!(
                "Falling back to first defined service in {}: {}",
                file.name(),
                service.proto().name()
            );
            return Some(if is_request {
                method.input_type()
            } else {
                method.output_type()
            });
        }
    }
    if let Some(method) = file.messages().next() {
        log::info!(
            "Falling back to first defined message in {}: {}",
            file.name(),
            method.proto().name()
        );
        return Some(method);
    }
    None
}

#[derive(Debug)]
struct RpcInfo {
    package: String,
    service: String,
    method: String,
}

impl RpcInfo {
    fn from_metadata(metadata: &dyn Metadata) -> Option<Self> {
        let path = metadata.get_path()?;
        if path.contains('?') {
            return None;
        }
        let mut parts = path.trim_start_matches('/').split('/');
        let service_and_package = parts.next()?;
        let method = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        let (package, service) = service_and_package
            .rsplit_once('.')
            .unwrap_or(("", service_and_package));

        Some(Self {
            package: package.to_string(),
            service: service.to_string(),
            method: method.to_string(),
        })
    }
}

impl std::fmt::Display for RpcInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.package.is_empty() {
            write!(f, "{}.", self.package)?;
        }
        write!(f, "{}.{}", self.service, self.method)
    }
}

fn parse_file_descriptor_set(definitions_path: &Path) -> anyhow::Result<Vec<FileDescriptor>> {
    let mut parser = Parser::new();
    parser.pure();
    if let Some(parent) = definitions_path.parent() {
        parser.include(parent);
    }
    parser.input(definitions_path);
    let fds = parser.file_descriptor_set()?;
    FileDescriptor::new_dynamic_fds(fds.file, &[])
        .context("failed to create dynamic file descriptors")
}
