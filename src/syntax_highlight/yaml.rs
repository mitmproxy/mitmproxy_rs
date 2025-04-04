use super::common::highlight;
use super::Chunk;
use anyhow::Result;

pub(crate) const YAML_TAGS: &[&str] = &[
    "boolean", "string", "number", "comment",  // # comment
    "type",     // !fixed32 type annotations
    "property", // key:
];

pub fn highlight_yaml(input: &[u8]) -> Result<Vec<Chunk>> {
    highlight(
        tree_sitter_yaml::LANGUAGE.into(),
        tree_sitter_yaml::HIGHLIGHTS_QUERY,
        YAML_TAGS,
        input,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax_highlight::common;

    #[test]
    fn test_tags_ok() {
        common::test_tags_ok(
            tree_sitter_yaml::LANGUAGE.into(),
            tree_sitter_yaml::HIGHLIGHTS_QUERY,
            YAML_TAGS,
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
                ("property", "string".to_string()),
                ("", ": ".to_string()),
                ("string", "\"value\"".to_string()),
                ("", "\n".to_string()),
                ("property", "bool".to_string()),
                ("", ": ".to_string()),
                ("boolean", "true".to_string()),
                ("", "\n".to_string()),
                ("property", "number".to_string()),
                ("", ": ".to_string()),
                ("type", "!fixed32".to_string()),
                ("", " ".to_string()),
                ("number", "42".to_string()),
                ("", "  ".to_string()),
                ("comment", "# comment".to_string()),
                ("", "\n".to_string())
            ]
        );
    }
}
