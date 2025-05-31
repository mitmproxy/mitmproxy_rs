use super::{common, Chunk, Tag};
use anyhow::Result;
use std::sync::LazyLock;
use tree_sitter_highlight::HighlightConfiguration;
use tree_sitter_javascript::HIGHLIGHT_QUERY as HIGHLIGHTS_QUERY;
use tree_sitter_javascript::LANGUAGE;

const NAMES: &[&str] = &[
    "keyword",  // let
    "function", // *function* () {
    "variable", // let *foo* = ...
    "property", // foo.*bar* = ...
    "constant", // *true*
    "string",   // "string"
    "number",   // 42
    "comment",  // /* comments */
];
const TAGS: &[Tag] = &[
    Tag::Name,
    Tag::Text,
    Tag::Text,
    Tag::Text,
    Tag::Boolean,
    Tag::String,
    Tag::Number,
    Tag::Comment,
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

    #[ignore]
    #[test]
    fn debug() {
        common::debug(
            LANGUAGE.into(),
            HIGHLIGHTS_QUERY,
            b"function foo() { let bar = true && 42 && 'qux'; foo.bar = 42; }  // comment",
        );
    }

    #[test]
    fn test_tags_ok() {
        common::test_tags_ok(LANGUAGE.into(), HIGHLIGHTS_QUERY, NAMES, TAGS);
    }

    #[test]
    fn test_highlight() {
        let input = b"\
        function foo() {\n\
          let bar = true && 42 && 'qux';\n\
        }  // comment\n\
        ";
        let chunks = highlight(input).unwrap();
        assert_eq!(
            chunks,
            vec![
                (Tag::Name, "function ".to_string()),
                (Tag::Text, "foo() {\n".to_string()),
                (Tag::Name, "let ".to_string()),
                (Tag::Text, "bar = ".to_string()),
                (Tag::Boolean, "true".to_string()),
                (Tag::Text, " && ".to_string()),
                (Tag::Number, "42".to_string()),
                (Tag::Text, " && ".to_string()),
                (Tag::String, "'qux'".to_string()),
                (Tag::Text, ";\n}  ".to_string()),
                (Tag::Comment, "// comment\n".to_string()),
            ]
        );
    }
}
