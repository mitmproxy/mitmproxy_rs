use super::{common, Chunk, Tag};
use anyhow::Result;
use std::sync::LazyLock;
use tree_sitter_css::HIGHLIGHTS_QUERY;
use tree_sitter_css::LANGUAGE;
use tree_sitter_highlight::HighlightConfiguration;

const NAMES: &[&str] = &[
    "tag",      // body
    "property", // font-size
    "variable", // --foo-bar
    "function", // calc()
    "number",   // 42
    "string",   // "foo"
    "comment",  // /* comment */
];
const TAGS: &[Tag] = &[
    Tag::Name,
    Tag::Boolean, // we only have one "Name", so this is a workaround.
    Tag::Text,
    Tag::Text,
    Tag::Number,
    Tag::String,
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
            b"p > span { color: red; font-size: 42px; content: \"foo\"; margin: var(--foo) } /* foo */",
        );
    }

    #[test]
    fn test_tags_ok() {
        common::test_tags_ok(LANGUAGE.into(), HIGHLIGHTS_QUERY, NAMES, TAGS);
    }

    #[test]
    fn test_highlight() {
        let input = b"\
        p > span { \n\
            color: red;\n\
            font-size: 42px;\n\
            content: \"foo\";\n\
            margin: var(--foo);\n\
        }\n\
        /* foo */\n\
        ";
        let chunks = highlight(input).unwrap();
        assert_eq!(
            chunks,
            vec![
                (Tag::Name, "p".to_string()),
                (Tag::Text, " > ".to_string()),
                (Tag::Name, "span".to_string()),
                (Tag::Text, " { \n".to_string()),
                (Tag::Boolean, "color".to_string()),
                (Tag::Text, ": red;\n".to_string()),
                (Tag::Boolean, "font-size".to_string()),
                (Tag::Text, ": ".to_string()),
                (Tag::Number, "42px".to_string()),
                (Tag::Text, ";\n".to_string()),
                (Tag::Boolean, "content".to_string()),
                (Tag::Text, ": ".to_string()),
                (Tag::String, "\"foo\"".to_string()),
                (Tag::Text, ";\n".to_string()),
                (Tag::Boolean, "margin".to_string()),
                (Tag::Text, ": var(--foo);\n}\n".to_string()),
                (Tag::Comment, "/* foo */\n".to_string()),
            ]
        );
    }
}
