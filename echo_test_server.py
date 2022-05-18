import asyncio
import logging
import signal
import sys
import time

from textwrap import dedent

import mitmproxy_wireguard

try:
    from rich import print
except ImportError:
    pass

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


async def main():
    logging.basicConfig(format=LOG_FORMAT, datefmt=TIME_FORMAT)
    logging.getLogger().setLevel(logging.DEBUG)
    logging.Formatter.convert = time.gmtime

    print(f"{dir(mitmproxy_wireguard)=}")

    k = mitmproxy_wireguard.genkey()
    print(f"mitmproxy_wireguard.genkey()={k!r}")
    print(f"{mitmproxy_wireguard.pubkey(k)=}")

    def receive_datagram(data, src_addr, dst_addr):
        print(f"Received datagram: {data=} {src_addr=} {dst_addr=}")
        server.send_datagram(data.upper(), dst_addr, src_addr)
        print("Echoed datagram.")

    server = await mitmproxy_wireguard.start_server(
        "0.0.0.0",
        51820,
        server_keypair[0],
        [(client_keypair[1], None)],
        handle_connection,
        receive_datagram,
    )
    print(f"{server.getsockname()=}")

    print(
        dedent(
            f"""
    :white_check_mark: Server started. Use the following WireGuard config for testing:
    ------------------------------------------------------------
    [Interface]
    PrivateKey = {client_keypair[0]}
    Address = 10.0.0.1/32
    
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
        print("Stopping server...")
        server.close()
        print("Stopped.")
        signal.signal(signal.SIGINT, lambda *_: sys.exit())

    signal.signal(signal.SIGINT, stop)

    await server.wait_closed()


async def handle_connection(rw: mitmproxy_wireguard.TcpStream):
    print(f"connection task {rw=}")
    print(f"{rw.get_extra_info('peername')=}")

    rw.write("Hi, I'm an echo server! 🦄\n".encode())

    for _ in range(2):
        print("reading...")
        try:
            data = await rw.read(4096)
        except Exception as exc:
            print(f"read {exc=}")
            data = b""
        print(f"read complete. writing... {len(data)=} {data[:10]=} ")

        try:
            rw.write(data.upper())
        except Exception as exc:
            print(f"write {exc=}")
        print("write complete. draining...")

        try:
            await rw.drain()
        except Exception as exc:
            print(f"drain {exc=}")
        print("drained.")

    print("closing...")
    try:
        rw.close()
    except Exception as exc:
        print(f"close {exc=}")
    print("closed.")


if __name__ == "__main__":
    asyncio.run(main(), debug=True)
