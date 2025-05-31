use super::common;
use super::{Chunk, Tag};
use anyhow::Result;
use std::sync::LazyLock;
use tree_sitter_highlight::HighlightConfiguration;
use tree_sitter_yaml::{HIGHLIGHTS_QUERY, LANGUAGE};

const NAMES: &[&str] = &[
    "boolean",  // YAML booleans
    "string",   // YAML strings
    "number",   // YAML numbers
    "comment",  // # comment
    "type",     // !fixed32 type annotations
    "property", // key:
];
const TAGS: &[Tag] = &[
    Tag::Boolean,
    Tag::String,
    Tag::Number,
    Tag::Comment,
    Tag::Name,
    Tag::Name,
];

static CONFIG: LazyLock<HighlightConfiguration> = LazyLock::new(|| {
    let mut config = HighlightConfiguration::new(LANGUAGE.into(), "", HIGHLIGHTS_QUERY, "", "")
        .expect("failed to build syntax highlighter");
    config.configure(NAMES);
    config
});

pub fn highlight(input: &[u8]) -> Result<Vec<Chunk>> {
    common::highlight(&CONFIG, TAGS, input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tags_ok() {
        common::test_tags_ok(LANGUAGE.into(), HIGHLIGHTS_QUERY, NAMES, TAGS);
    }

    #[test]
    fn test_highlight() {
        let input = b"\
        string: \"value\"\n\
        bool: true\n\
        number: !fixed32 42  # comment\n\
        ";
        let chunks = highlight(input).unwrap();
        assert_eq!(
            chunks,
            vec![
                (Tag::Name, "string".to_string()),
                (Tag::Text, ": ".to_string()),
                (Tag::String, "\"value\"\n".to_string()),
                (Tag::Name, "bool".to_string()),
                (Tag::Text, ": ".to_string()),
                (Tag::Boolean, "true\n".to_string()),
                (Tag::Name, "number".to_string()),
                (Tag::Text, ": ".to_string()),
                (Tag::Name, "!fixed32 ".to_string()),
                (Tag::Number, "42  ".to_string()),
                (Tag::Comment, "# comment\n".to_string()),
            ]
        );
    }
}
