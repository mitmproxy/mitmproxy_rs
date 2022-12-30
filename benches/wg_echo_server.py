import asyncio
import logging
import signal
import sys
import time

import mitmproxy_rs


LOG_FORMAT = "[%(asctime)s %(levelname)-5s %(name)s] %(message)s"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

try:
    from rich import print
    from rich.logging import RichHandler

    logging.basicConfig(format=LOG_FORMAT, datefmt=TIME_FORMAT, handlers=[RichHandler()])
except ImportError:
    logging.basicConfig(format=LOG_FORMAT, datefmt=TIME_FORMAT)

logging.Formatter.convert = time.gmtime
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


# (private key, public key)
server_keypair = (
    "EG47ZWjYjr+Y97TQ1A7sVl7Xn3mMWDnvjU/VxU769ls=",
    "mitmV5Wo7pRJrHNAKhZEI0nzqqeO8u4fXG+zUbZEXA0=",
)
client_keypair = (
    "qG8b7LI/s+ezngWpXqj5A7Nj988hbGL+eQ8ePki0iHk=",
    "Test1sbpTFmJULgSlJ5hJ1RdzsXWrl3Mg7k9UTN//jE=",
)


async def main():
    server = await mitmproxy_rs.start_wireguard_server(
        "0.0.0.0",
        51820,
        server_keypair[0],
        [client_keypair[1]],
        handle_connection,
        receive_datagram,
    )

    print(
        f"""
------------------------------------------------------------
[Interface]
PrivateKey = {client_keypair[0]}
Address = 10.0.0.1/32
MTU = 1420

[Peer]
PublicKey = {server_keypair[1]}
AllowedIPs = 10.0.0.0/24
Endpoint = 127.0.0.1:51820
------------------------------------------------------------
"""
    )

    def stop(*_):
        server.close()
        signal.signal(signal.SIGINT, lambda *_: sys.exit())

    signal.signal(signal.SIGINT, stop)

    await server.wait_closed()


async def handle_connection(rw: mitmproxy_rs.TcpStream):
    logger.debug(f"Connection established: {rw}")

    while True:
        data = await rw.read(4096)

        # check if the connection was closed
        if len(data) == 0:
            break

        rw.write(data)
        await rw.drain()

    rw.close()
    logger.debug(f"Connection closed: {rw}")


def receive_datagram(_data, _src_addr, _dst_addr):
    pass


if __name__ == "__main__":
    asyncio.run(main(), debug=True)
