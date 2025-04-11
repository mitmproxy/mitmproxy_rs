mod grpc;
mod hex_dump;
mod hex_stream;
mod msgpack;
mod protobuf;

pub use grpc::GRPC;
pub use hex_dump::HexDump;
pub use hex_stream::HexStream;
pub use msgpack::MsgPack;
pub use protobuf::Protobuf;

use anyhow::Result;
use mitmproxy_highlight::Language;

pub trait Metadata {
    /// The HTTP `content-type` of this message.
    fn content_type(&self) -> Option<&str>;
    /// Get an HTTP header value by name.
    /// `name` is case-insensitive.
    fn get_header(&self, name: &str) -> Option<String>;
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
    fn render_priority(&self, data: &[u8], metadata: &dyn Metadata) -> f64 {
        0.0
    }
}

pub trait Reencode: Send + Sync {
    fn reencode(&self, data: &str, metadata: &dyn Metadata) -> Result<Vec<u8>>;
}

// no cfg(test) gate because it's used in benchmarks as well
pub mod test {
    use crate::Metadata;

    #[derive(Default)]
    pub struct TestMetadata {
        pub content_type: Option<String>,
        pub headers: std::collections::HashMap<String, String>,
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
    }

    impl Metadata for TestMetadata {
        fn content_type(&self) -> Option<&str> {
            self.content_type.as_deref()
        }

        fn get_header(&self, name: &str) -> Option<String> {
            self.headers.get(&name.to_lowercase()).cloned()
        }
    }
}
