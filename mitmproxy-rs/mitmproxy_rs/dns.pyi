from __future__ import annotations
from typing import final

@final
class DnsResolver:
    def __init__(
        self, *, name_servers: list[str] | None = None, use_hosts_file: bool = True
    ) -> None: ...
    async def lookup_ip(self, host: str) -> list[str]: ...
    async def lookup_ipv4(self, host: str) -> list[str]: ...
    async def lookup_ipv6(self, host: str) -> list[str]: ...

def get_system_dns_servers() -> list[str]: ...

__all__ = [
    "DnsResolver",
    "get_system_dns_servers",
]
