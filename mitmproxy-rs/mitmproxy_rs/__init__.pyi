from __future__ import annotations

from typing import Any, Literal
from typing import final, overload, TypeVar
from . import certs, contentviews, dns, local, process_info, tun, udp, wireguard, syntax_highlight

T = TypeVar("T")

# TCP / UDP

@final
class Stream:
    async def read(self, n: int) -> bytes: ...
    def write(self, data: bytes): ...
    async def drain(self) -> None: ...
    def write_eof(self): ...
    def close(self): ...
    def is_closing(self) -> bool: ...
    async def wait_closed(self) -> None: ...
    @overload
    def get_extra_info(
        self, name: Literal["transport_protocol"], default: None = None
    ) -> Literal["tcp", "udp"]: ...
    @overload
    def get_extra_info(
        self, name: Literal["transport_protocol"], default: T
    ) -> Literal["tcp", "udp"] | T: ...
    @overload
    def get_extra_info(
        self,
        name: Literal[
            "peername", "sockname", "original_src", "original_dst", "remote_endpoint"
        ],
        default: None = None,
    ) -> tuple[str, int]: ...
    @overload
    def get_extra_info(
        self,
        name: Literal[
            "peername", "sockname", "original_src", "original_dst", "remote_endpoint"
        ],
        default: T,
    ) -> tuple[str, int] | T: ...
    @overload
    def get_extra_info(self, name: Literal["pid"], default: None = None) -> int: ...
    @overload
    def get_extra_info(self, name: Literal["pid"], default: T) -> int | T: ...
    @overload
    def get_extra_info(
        self, name: Literal["process_name"], default: None = None
    ) -> str: ...
    @overload
    def get_extra_info(self, name: Literal["process_name"], default: T) -> str | T: ...
    @overload
    def get_extra_info(self, name: str, default: Any) -> Any: ...
    def __repr__(self) -> str: ...

__all__ = [
    "certs",
    "contentviews",
    "dns",
    "local",
    "process_info",
    "syntax_highlight",
    "tun",
    "udp",
    "wireguard",
    "Stream",
]
