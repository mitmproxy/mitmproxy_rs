use criterion::{criterion_group, criterion_main, Criterion};
use mitmproxy_contentviews::{test::TestMetadata, MsgPack, Prettify, Protobuf, Reencode};
use std::hint::black_box;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("protobuf-prettify", |b| {
        b.iter(|| {
            Protobuf.prettify(black_box(b"\n\x13gRPC testing server\x12\x07\n\x05Index\x12\x07\n\x05Empty\x12\x0c\n\nDummyUnary\x12\x0f\n\rSpecificError\x12\r\n\x0bRandomError\x12\x0e\n\x0cHeadersUnary\x12\x11\n\x0fNoResponseUnary"), &TestMetadata::default()).unwrap()
        })
    });

    c.bench_function("protobuf-reencode", |b| {
        b.iter(|| {
            Protobuf.reencode(
                black_box("1: gRPC testing server\n2:\n- 1: Index\n- 1: Empty\n- 1: DummyUnary\n- 1: SpecificError\n- 1: RandomError\n- 1: HeadersUnary\n- 1: NoResponseUnary\n"),
                &TestMetadata::default()
            ).unwrap()
        })
    });

    const TEST_MSGPACK: &[u8] = &[
        0x83, // map with 3 elements
        0xa4, 0x6e, 0x61, 0x6d, 0x65, // "name"
        0xa8, 0x4a, 0x6f, 0x68, 0x6e, 0x20, 0x44, 0x6f, 0x65, // "John Doe"
        0xa3, 0x61, 0x67, 0x65, // "age"
        0x1e, // 30
        0xa4, 0x74, 0x61, 0x67, 0x73, // "tags"
        0x92, // array with 2 elements
        0xa9, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x72, // "developer"
        0xa4, 0x72, 0x75, 0x73, 0x74, // "rust"
    ];
    c.bench_function("msgpack-prettify", |b| {
        b.iter(|| {
            MsgPack
                .prettify(black_box(TEST_MSGPACK), &TestMetadata::default())
                .unwrap()
        })
    });

    c.bench_function("msgpack-reencode", |b| {
        b.iter(|| {
            MsgPack
                .reencode(
                    black_box(
                        "\
                name: John Doe\n\
                age: 30\n\
                tags:\n\
                - developer\n\
                - rust\n\
                ",
                    ),
                    &TestMetadata::default(),
                )
                .unwrap()
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
