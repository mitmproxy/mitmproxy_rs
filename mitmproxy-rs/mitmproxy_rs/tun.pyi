from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import final
from . import Stream

async def create_tun_interface(
    handle_tcp_stream: Callable[[Stream], Awaitable[None]],
    handle_udp_stream: Callable[[Stream], Awaitable[None]],
    tun_name: str | None = None,
) -> TunInterface: ...
@final
class TunInterface:
    def tun_name(self) -> str: ...
    def close(self) -> None: ...
    async def wait_closed(self) -> None: ...
    def __repr__(self) -> str: ...
    @staticmethod
    def unavailable_reason() -> str | None: ...

__all__ = [
    "create_tun_interface",
    "TunInterface",
]
