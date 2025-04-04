use super::common::highlight;
use super::{Chunk, Tag};
use anyhow::Result;

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

pub fn highlight_yaml(input: &[u8]) -> Result<Vec<Chunk>> {
    highlight(
        tree_sitter_yaml::LANGUAGE.into(),
        tree_sitter_yaml::HIGHLIGHTS_QUERY,
        NAMES,
        TAGS,
        input,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax_highlight::common;

    #[test]
    fn test_tags_ok() {
        common::test_names_ok(
            tree_sitter_yaml::LANGUAGE.into(),
            tree_sitter_yaml::HIGHLIGHTS_QUERY,
            NAMES,
            TAGS,
        );
    }

    #[test]
    fn test_highlight_yaml() {
        let input = b"\
        string: \"value\"\n\
        bool: true\n\
        number: !fixed32 42  # comment\n\
        ";
        let chunks = highlight_yaml(input).unwrap();
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
