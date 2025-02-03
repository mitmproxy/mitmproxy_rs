from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import final
from . import Stream

def genkey() -> str: ...
def pubkey(private_key: str) -> str: ...
async def start_wireguard_server(
    host: str,
    port: int,
    private_key: str,
    peer_public_keys: list[str],
    handle_tcp_stream: Callable[[Stream], Awaitable[None]],
    handle_udp_stream: Callable[[Stream], Awaitable[None]],
) -> WireGuardServer: ...
@final
class WireGuardServer:
    def getsockname(self) -> tuple[str, int]: ...
    def close(self) -> None: ...
    async def wait_closed(self) -> None: ...
    def __repr__(self) -> str: ...

__all__ = [
    "genkey",
    "pubkey",
    "start_wireguard_server",
    "WireGuardServer",
]
