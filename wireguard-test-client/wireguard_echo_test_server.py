import asyncio
import logging
import signal
import sys
import textwrap
import time

import mitmproxy_rs

# (private key, public key)
server_keypair = (
    "EG47ZWjYjr+Y97TQ1A7sVl7Xn3mMWDnvjU/VxU769ls=",
    "mitmV5Wo7pRJrHNAKhZEI0nzqqeO8u4fXG+zUbZEXA0=",
)
client_keypair = (
    "qG8b7LI/s+ezngWpXqj5A7Nj988hbGL+eQ8ePki0iHk=",
    "Test1sbpTFmJULgSlJ5hJ1RdzsXWrl3Mg7k9UTN//jE=",
)

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


async def main():
    def receive_datagram(data, src_addr, dst_addr):
        logger.debug(f"Received datagram: {data=} {src_addr=} {dst_addr=}")
        server.send_datagram(data.upper(), dst_addr, src_addr)
        logger.debug("Echoed datagram.")

    server = await mitmproxy_rs.start_wireguard_server(
        "0.0.0.0",
        51820,
        server_keypair[0],
        [client_keypair[1]],
        handle_connection,
        receive_datagram,
    )

    print(
        textwrap.dedent(
            f"""
    :white_check_mark: Server started. Use the following WireGuard config for testing:
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
    
    And then run `nc 10.0.0.42 1234` or `nc -u 10.0.0.42 1234` to talk to the echo server.
    """
        )
    )

    def stop(*_):
        server.close()
        signal.signal(signal.SIGINT, lambda *_: sys.exit())

    signal.signal(signal.SIGINT, stop)

    await server.wait_closed()


async def handle_connection(rw: mitmproxy_rs.TcpStream):
    logger.debug(f"connection task {rw=}")
    logger.debug(f"{rw.get_extra_info('peername')=}")

    for _ in range(2):
        logger.debug("reading...")
        try:
            data = await rw.read(4096)
        except Exception as exc:
            logger.debug(f"read {exc=}")
            data = b""
        logger.debug(f"read complete. writing... {len(data)=} {data[:10]=} ")

        try:
            rw.write(data.upper())
        except Exception as exc:
            logger.debug(f"write {exc=}")
        logger.debug("write complete. draining...")

        try:
            await rw.drain()
        except Exception as exc:
            logger.debug(f"drain {exc=}")
        logger.debug("drained.")

    logger.debug("closing...")
    try:
        rw.close()
    except Exception as exc:
        logger.debug(f"close {exc=}")
    logger.debug("closed.")


if __name__ == "__main__":
    asyncio.run(main(), debug=True)
