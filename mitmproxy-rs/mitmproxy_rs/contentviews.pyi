from typing import ClassVar, final

class Contentview:
    name: ClassVar[str]

    def prettify(self, data: bytes) -> str:
        pass

@final
class InteractiveContentview(Contentview):
    def reencode(self, data: str) -> bytes:
        pass

hex_dump: Contentview
hex_stream: InteractiveContentview
msgpack: InteractiveContentview

__all__ = [
    "Contentview",
    "InteractiveContentview",
    "hex_dump",
    "hex_stream",
    "msgpack",
]
