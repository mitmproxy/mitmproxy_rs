mod hex_dump;
mod hex_stream;
mod msgpack;
mod protobuf;
mod test_inspect_metadata;

pub use hex_dump::HexDump;
pub use hex_stream::HexStream;
pub use msgpack::MsgPack;
pub use protobuf::Protobuf;
pub use protobuf::GRPC;
pub use test_inspect_metadata::TestInspectMetadata;

use anyhow::Result;
use mitmproxy_highlight::Language;

use serde::Serialize;
use std::path::Path;

pub trait Metadata {
    /// The HTTP `content-type` of this message.
    fn content_type(&self) -> Option<&str>;
    /// Get an HTTP header value by name.
    /// `name` is case-insensitive.
    fn get_header(&self, name: &str) -> Option<String>;
    /// Get the path from the flow's request.
    fn get_path(&self) -> Option<&str> {
        None
    }
    /// Check if this is an HTTP request.
    fn is_http_request(&self) -> bool {
        false
    }
    /// Get the protobuf definitions for this message.
    fn protobuf_definitions(&self) -> Option<&Path> {
        None
    }
}

/// See https://docs.mitmproxy.org/dev/api/mitmproxy/contentviews.html
/// for API details.
pub trait Prettify: Send + Sync {
    /// The name for this contentview, e.g. `gRPC` or `Protobuf`.
    /// Favor brevity.
    fn name(&self) -> &str;

    fn instance_name(&self) -> String {
        self.name().to_lowercase().replace(" ", "_")
    }

    /// The syntax highlighting that should be applied to the prettified output.
    /// This is useful for contentviews that prettify to JSON or YAML.
    fn syntax_highlight(&self) -> Language {
        Language::None
    }

    /// Pretty-print `data`.
    fn prettify(&self, data: &[u8], metadata: &dyn Metadata) -> Result<String>;

    /// Render priority - typically a float between 0 and 1 for builtin views.
    #[allow(unused_variables)]
    fn render_priority(&self, data: &[u8], metadata: &dyn Metadata) -> f32 {
        0.0
    }
}

pub trait Reencode: Send + Sync {
    fn reencode(&self, data: &str, metadata: &dyn Metadata) -> Result<Vec<u8>>;
}

// no cfg(test) gate because it's used in benchmarks as well
pub mod test {
    use super::*;

    #[derive(Default, Serialize)]
    pub struct TestMetadata {
        pub content_type: Option<String>,
        pub headers: std::collections::HashMap<String, String>,
        pub protobuf_definitions: Option<std::path::PathBuf>,
        pub path: Option<String>,
        pub is_http_request: bool,
    }

    impl TestMetadata {
        pub fn with_content_type(mut self, content_type: &str) -> Self {
            self.content_type = Some(content_type.to_string());
            self
        }

        pub fn with_header(mut self, name: &str, value: &str) -> Self {
            self.headers.insert(name.to_lowercase(), value.to_string());
            self
        }

        pub fn with_path(mut self, path: &str) -> Self {
            self.path = Some(path.to_string());
            self
        }

        pub fn with_protobuf_definitions<P: AsRef<Path>>(mut self, definitions: P) -> Self {
            self.protobuf_definitions = Some(definitions.as_ref().to_path_buf());
            self
        }

        pub fn with_is_http_request(mut self, is_http_request: bool) -> Self {
            self.is_http_request = is_http_request;
            self
        }
    }

    impl Metadata for TestMetadata {
        fn content_type(&self) -> Option<&str> {
            self.content_type.as_deref()
        }

        fn get_header(&self, name: &str) -> Option<String> {
            self.headers.get(name).cloned()
        }

        fn get_path(&self) -> Option<&str> {
            self.path.as_deref()
        }

        fn protobuf_definitions(&self) -> Option<&Path> {
            self.protobuf_definitions.as_deref()
        }

        fn is_http_request(&self) -> bool {
            self.is_http_request
        }
    }
}
