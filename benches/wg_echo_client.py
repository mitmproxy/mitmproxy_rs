import asyncio
import logging
import pprint
import signal
import sys
import textwrap
import time
import timeit


# generate 10000 unique test packets with the given length
def gen_data(pnum: int, psize: int) -> list[bytes]:
    packets = []

    for i in range(pnum):
        packet = (f"{i:04d}".encode() * (psize // 4 + 1))[:psize]
        packets.append(packet)

    return packets


async def work(bytes_out: list[bytes]):
    r, w = await asyncio.open_connection("10.0.0.42", 1234)

    bytes_back = []

    # send and receive 10000 packets of 1 KiB each
    for packet in bytes_out:
        w.write(packet)
        await w.drain()

        recv_len = 0
        recv_bytes = []

        while recv_len != len(packet):
            read = await r.read(4096)
            recv_bytes.extend(read)
            recv_len += len(read)

        bytes_back.append(bytes(recv_bytes))

    w.close()
    await w.wait_closed()

    try:
        assert bytes_out == bytes_back

    except AssertionError:
        bytes_sent = sum(map(len, bytes_out))
        bytes_received = sum(map(len, bytes_back))

        pprint.pprint(bytes_out)
        pprint.pprint(bytes_back)

        print(f"Bytes Sent: {bytes_sent}")
        print(f"Bytes Received: {bytes_received}")
        print(f"Difference: {bytes_sent - bytes_received}")

        raise


if __name__ == "__main__":
    numbs = [10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000]
    sizes = [10, 20, 50, 100, 200, 500, 1000, 2000, 4096]

    for numb in numbs:
        for size in sizes:
            data = gen_data(numb, size)
            timer = timeit.Timer(lambda: asyncio.run(work(data), debug=True))
            print(f"Packet number: {numb}")
            print(f"Packet size: {size} bytes")
            print(timer.repeat(10, number=1))
            print()
