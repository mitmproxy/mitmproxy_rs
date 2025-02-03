from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import final
from . import Stream

async def start_udp_server(
    host: str,
    port: int,
    handle_udp_stream: Callable[[Stream], Awaitable[None]],
) -> UdpServer: ...
@final
class UdpServer:
    def getsockname(self) -> tuple[str, int]: ...
    def close(self) -> None: ...
    async def wait_closed(self) -> None: ...
    def __repr__(self) -> str: ...

async def open_udp_connection(
    host: str,
    port: int,
    *,
    local_addr: tuple[str, int] | None = None,
) -> Stream: ...

__all__ = [
    "start_udp_server",
    "UdpServer",
    "open_udp_connection",
]
