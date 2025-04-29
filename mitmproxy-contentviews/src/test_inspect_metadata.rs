use crate::test::TestMetadata;
use crate::{Metadata, Prettify};
use anyhow::Context;
use std::collections::HashMap;
use std::path::Path;

/// Contentview used for internal testing to ensure that the
/// Python accessors in mitmproxy-rs all work properly.
pub struct TestInspectMetadata;

impl Prettify for TestInspectMetadata {
    fn name(&self) -> &'static str {
        "Inspect Metadata (test only)"
    }

    fn instance_name(&self) -> String {
        "_test_inspect_metadata".to_string()
    }

    fn prettify(&self, _data: &[u8], metadata: &dyn Metadata) -> anyhow::Result<String> {
        let mut headers = HashMap::new();
        if let Some(host) = metadata.get_header("host") {
            headers.insert("host".to_string(), host);
        }
        let meta = TestMetadata {
            content_type: metadata.content_type().map(str::to_string),
            headers,
            path: metadata.get_path().map(str::to_string),
            is_http_request: metadata.is_http_request(),
            protobuf_definitions: metadata.protobuf_definitions().map(Path::to_path_buf),
        };
        // JSON would be nicer to consume on the Python side,
        // but let's not add dependencies for this.
        serde_yaml::to_string(&meta).context("Failed to convert to YAML")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prettify_simple() {
        let result = TestInspectMetadata
            .prettify(b"", &TestMetadata::default())
            .unwrap();
        assert_eq!(
            result,
            "content_type: null\nheaders: {}\nprotobuf_definitions: null\npath: null\nis_http_request: false\n"
        );
    }
}
