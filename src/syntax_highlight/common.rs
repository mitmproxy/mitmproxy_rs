use super::Chunk;
use anyhow::{Context, Result};
use tree_sitter_highlight::{HighlightConfiguration, HighlightEvent, Highlighter};

pub fn highlight(
    language: tree_sitter::Language,
    highlights_query: &str,
    tags: &[&'static str],
    input: &[u8],
) -> Result<Vec<Chunk>> {
    let mut highlighter = Highlighter::new();
    let mut config = HighlightConfiguration::new(language, "", highlights_query, "", "")
        .context("failed to create highlight configuration")?;
    config.configure(tags);

    let highlights = highlighter
        .highlight(&config, input, None, |_| None)
        .context("failed to highlight")?;

    let mut chunks: Vec<Chunk> = Vec::new();
    let mut tag: Option<&'static str> = None;

    for event in highlights {
        let event = event.context("highlighter failure")?;
        match event {
            HighlightEvent::Source { start, end } => {
                let contents = &input[start..end];
                let tag_str = tag.unwrap_or("");
                
                match chunks.last_mut() {
                    Some(x) if x.0 == tag_str => {
                        x.1.push_str(&String::from_utf8_lossy(contents));
                    }
                    _ => chunks.push(
                        (tag_str, String::from_utf8_lossy(contents).to_string())
                    ),
                }
            }
            HighlightEvent::HighlightStart(s) => {
                tag = Some(tags[s.0]);
            }
            HighlightEvent::HighlightEnd => {
                tag = None;
            }
        }
    }
    Ok(chunks)
}

#[cfg(test)]
pub(super) fn test_tags_ok(
    language: tree_sitter::Language,
    highlights_query: &str,
    tags: &[&'static str],
) {
    let config = HighlightConfiguration::new(language, "", highlights_query, "", "").unwrap();
    for &tag in tags {
        assert!(
            config.names().iter().any(|name| name.contains(tag)),
            "Invalid tag: {},\nAllowed tags: {:?}",
            tag,
            config.names()
        );
    }
}
