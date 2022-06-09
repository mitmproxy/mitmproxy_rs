import asyncio
import logging
import signal
import sys
import textwrap
import time
import timeit


def gen_data() -> list[bytes]:
    data = []
    for i in range(10000):
        packet = f"{i:04d}".encode() * 256
        data.append(packet)
    return data


async def main(bytes_out: list[bytes]):
    r, w = await asyncio.open_connection("0.0.0.0", 51820)

    bytes_back = []

    # send and receive 10000 packets of 1 KiB each
    for packet in bytes_out:
        w.write(packet)
        await w.drain()

        read = await r.read(4096)
        bytes_back.append(read)

    w.close()
    await w.wait_closed()

    try:
        assert bytes_out == bytes_back

    except AssertionError:
        bytes_sent = sum(map(len, bytes_out))
        bytes_received = sum(map(len, bytes_back))

        print(f"Bytes Sent: {bytes_sent}")
        print(f"Bytes Received: {bytes_received}")
        print(f"Difference: {bytes_sent - bytes_received}")


if __name__ == "__main__":
    bytes_out = gen_data()
    print(timeit.timeit(lambda: asyncio.run(main(bytes_out), debug=True), number=10))
