use criterion::{criterion_group, criterion_main, Criterion};
use mitmproxy_highlight::Language;
use std::hint::black_box;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("syntax_highlight small", |b| {
        b.iter(|| {
            Language::Xml
                .highlight(black_box(
                    br#"
            <!doctype html>
            <html lang="en">
              <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Bootstrap demo</title>
              </head>
              <body>
                <h1>Hello, world!</h1>
              </body>
            </html>"#,
                ))
                .unwrap()
        })
    });

    let data = "<a>x".repeat(8096);
    c.bench_function("syntax_highlight xml", |b| {
        b.iter(|| Language::Xml.highlight(black_box(data.as_bytes())).unwrap())
    });

    // tree_sitter_html is faster, but not by orders of magnitude.
    /*
    let mut config = HighlightConfiguration::new(
        tree_sitter_html::LANGUAGE.into(),
        "",
        tree_sitter_html::HIGHLIGHTS_QUERY,
        "",
        ""
    ).unwrap();
    let names = config.names().iter().map(|x| x.to_string()).collect::<Vec<String>>();
    let tags = names.iter().map(|_| Tag::Text).collect::<Vec<Tag>>();
    config.configure(&names);

    c.bench_function("syntax_highlight html", |b| {
        b.iter(|| {
            common::highlight(
                &config,
                &tags,
                data.as_bytes(),
            )
        })
    });
    */
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
