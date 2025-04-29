from __future__ import annotations

from typing import ClassVar, final, Literal

class Contentview:
    name: ClassVar[str]

    syntax_highlight: ClassVar[Literal["xml", "yaml", "none", "error"]]

    def prettify(self, data: bytes, metadata) -> str:
        pass

    def render_priority(self, data: bytes, metadata) -> float:
        pass

@final
class InteractiveContentview(Contentview):
    def reencode(self, data: str, metadata) -> bytes:
        pass

_test_inspect_metadata: Contentview
hex_dump: Contentview
hex_stream: InteractiveContentview
msgpack: InteractiveContentview
protobuf: InteractiveContentview
grpc: InteractiveContentview

__all__ = [
    "Contentview",
    "InteractiveContentview",
    "hex_dump",
    "hex_stream",
    "msgpack",
    "protobuf",
    "grpc",
    "_test_inspect_metadata",
]
