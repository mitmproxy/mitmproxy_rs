import asyncio
import logging
import signal
import sys
import textwrap
import time
import timeit


# generate 10000 unique test packets with the given length
def gen_data(psize: int) -> list[bytes]:
    packets = []

    for i in range(10000):
        packet = (f"{i:04d}".encode() * (psize // 4 + 1))[:psize]
        packets.append(packet)

    return packets


async def main(bytes_out: list[bytes]):
    r, w = await asyncio.open_connection("10.0.0.42", 1234)

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
    sizes = [10, 20, 50, 100, 200, 500, 1000, 2000, 5000]

    for size in sizes:
        data = gen_data(size)
        timer = timeit.Timer(lambda: asyncio.run(main(data), debug=True))
        print(f"Packet size: {size} bytes")
        print(timer.repeat(10, number=1))
