from collections.abc import Callable


class ConnectionEstablished:
    connection_id: int
    src_addr: tuple
    dst_addr: tuple


class DataReceived:
    connection_id: int
    data: bytes


class ConnectionClosed:
    connection_id: int


class DatagramReceived:
    src_addr: tuple
    dst_addr: tuple
    data: bytes


async def start_server(
    host: str,
    port: int,
    on_event: Callable[ConnectionEstablished | DataReceived | ConnectionClosed | DatagramReceived]
):
    ...
