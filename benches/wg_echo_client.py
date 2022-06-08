import asyncio
import logging
import signal
import sys
import textwrap
import time
import timeit


async def main():
    r, w = await asyncio.open_connection("10.0.0.42", 1234)

    bytes_out = []
    bytes_back = []

    # send and receive 10000 packets of 1 KiB each
    for i in range(10000):
        data = f"{i:04d}".encode() * 256

        w.write(data)
        bytes_out.extend(data)
        await w.drain()

        read = await r.read(4096)
        bytes_back.extend(read)

    w.close()
    await w.wait_closed()

    try:
        assert bytes_out == bytes_back

    except AssertionError:
        print(f"Bytes Sent: {len(bytes_out)}")
        print(f"Bytes Received: {len(bytes_back)}")
        print(f"Difference: {len(bytes_out) - len(bytes_back)}")


if __name__ == "__main__":
    print(timeit.timeit(lambda: asyncio.run(main(), debug=True), number=10))
