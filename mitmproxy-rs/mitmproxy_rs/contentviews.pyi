from typing import ClassVar, final

class Contentview:
    name: ClassVar[str]

    def prettify(self, data: bytes, metadata) -> str:
        pass

@final
class InteractiveContentview(Contentview):
    def reencode(self, data: str, metadata) -> bytes:
        pass

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
]
