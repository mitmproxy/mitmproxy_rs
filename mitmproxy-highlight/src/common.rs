use super::{Chunk, Tag};
use anyhow::{Context, Result};
use tree_sitter_highlight::{HighlightConfiguration, HighlightEvent, Highlighter};

pub fn highlight(
    config: &HighlightConfiguration,
    tags: &[Tag],
    input: &[u8],
) -> Result<Vec<Chunk>> {
    let mut highlighter = Highlighter::new();
    let highlights = highlighter
        .highlight(config, input, None, |_| None)
        .context("failed to highlight")?;

    let mut chunks: Vec<Chunk> = Vec::new();
    let mut tag: Tag = Tag::Text;

    for event in highlights {
        let event = event.context("highlighter failure")?;
        match event {
            HighlightEvent::Source { start, end } => {
                let contents = String::from_utf8_lossy(&input[start..end]);
                match chunks.last_mut() {
                    Some(x) if x.0 == tag || contents.trim_ascii().is_empty() => {
                        x.1.push_str(&contents);
                    }
                    _ => chunks.push((tag, contents.to_string())),
                }
            }
            HighlightEvent::HighlightStart(s) => {
                tag = tags[s.0];
            }
            HighlightEvent::HighlightEnd => {
                tag = Tag::Text;
            }
        }
    }
    Ok(chunks)
}

#[cfg(test)]
pub(super) fn test_tags_ok(
    language: tree_sitter::Language,
    highlights_query: &str,
    names: &[&str],
    tags: &[Tag],
) {
    assert_eq!(names.len(), tags.len());
    let config = HighlightConfiguration::new(language, "", highlights_query, "", "").unwrap();
    for &tag in names {
        assert!(
            config.names().iter().any(|name| name.contains(tag)),
            "Invalid tag: {},\nAllowed tags: {:?}",
            tag,
            config.names()
        );
    }
}

#[allow(unused)]
#[cfg(test)]
pub(super) fn debug(language: tree_sitter::Language, highlights_query: &str, input: &[u8]) {
    let mut highlighter = Highlighter::new();
    let mut config = HighlightConfiguration::new(language, "", highlights_query, "", "").unwrap();
    let names = config
        .names()
        .iter()
        .map(|name| name.to_string())
        .collect::<Vec<_>>();
    config.configure(&names);
    let highlights = highlighter
        .highlight(&config, input, None, |_| None)
        .unwrap();

    let mut tag: &str = "";
    for event in highlights {
        match event.unwrap() {
            HighlightEvent::Source { start, end } => {
                let contents = &input[start..end];
                println!(
                    "{}: {:?}",
                    tag,
                    String::from_utf8_lossy(contents).to_string().as_str()
                );
            }
            HighlightEvent::HighlightStart(s) => {
                tag = &names[s.0];
            }
            HighlightEvent::HighlightEnd => {
                tag = "";
            }
        }
    }
}
