import asyncio
import os
import signal
import sys
from textwrap import dedent

try:
    from rich import print
except ImportError:
    pass

os.environ["RUST_LOG"] = "mitmproxy_wireguard=debug"

import mitmproxy_wireguard

# (private key, public key)
server_keypair = ("EG47ZWjYjr+Y97TQ1A7sVl7Xn3mMWDnvjU/VxU769ls=", "mitmV5Wo7pRJrHNAKhZEI0nzqqeO8u4fXG+zUbZEXA0=")
client_keypair = ("qG8b7LI/s+ezngWpXqj5A7Nj988hbGL+eQ8ePki0iHk=", "Test1sbpTFmJULgSlJ5hJ1RdzsXWrl3Mg7k9UTN//jE=")


async def main():
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
        [client_keypair[1]],
        handle_connection,
        receive_datagram
    )
    print(f"{server.getsockname()=}")

    print(dedent(f"""
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
    """))

    def stop(*_):
        print("Stopping server...")
        server.stop()
        print("Stopped.")
        signal.signal(signal.SIGINT, lambda *_: sys.exit())

    signal.signal(signal.SIGINT, stop)
    await asyncio.sleep(9999)


async def handle_connection(r: asyncio.StreamReader, w: asyncio.StreamWriter):
    print(f"connection task {w=}")
    print(f"{w.get_extra_info('peername')=}")

    w.write("Hi, I'm an echo server! 🦄\n".encode())

    for _ in range(2):
        print("reading...")
        try:
            data = await r.read(4096)
        except Exception as exc:
            print(f"read {exc=}")
            data = b""
        print(f"read complete. writing... {len(data)=} {data[:10]=} ")

        try:
            w.write(data.upper())
        except Exception as exc:
            print(f"write {exc=}")
        print("write complete. draining...")

        try:
            await w.drain()
        except Exception as exc:
            print(f"drain {exc=}")
        print("drained.")

    print("closing...")
    try:
        w.close()
    except Exception as exc:
        print(f"close {exc=}")
    print("closed.")


if __name__ == "__main__":
    asyncio.run(main(), debug=True)
