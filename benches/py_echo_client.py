import argparse
import asyncio
import json
import pprint
import timeit


# generate unique test packets with the given length
def gen_data(pnum: int, psize: int) -> list[bytes]:
    packets = []

    for i in range(pnum):
        packet = (f"{i:04d}".encode() * (psize // 4 + 1))[:psize]
        assert len(packet) == psize
        packets.append(packet)

    return packets


async def work(host: str, port: int, packets: list[bytes]):
    r, w = await asyncio.open_connection(host, port)

    bytes_back = []

    for packet in packets:
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
        assert packets == bytes_back

    except AssertionError:
        bytes_sent = sum(map(len, packets))
        bytes_received = sum(map(len, bytes_back))

        pprint.pprint(packets)
        pprint.pprint(bytes_back)

        print(f"Bytes Sent: {bytes_sent}")
        print(f"Bytes Received: {bytes_received}")
        print(f"Difference: {bytes_sent - bytes_received}")

        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("name", choices=["local", "nonlocal"])
    parser.add_argument("host", default="0.0.0.0")
    parser.add_argument("port", default=51820)
    args = parser.parse_args()

    # host = "192.168.86.134"
    name = args.name
    host = args.host
    port = args.port

    reps = 10
    numbs = [1000, 2000, 5000, 10000, 20000, 50000, 100000]
    sizes = [1000]

    x = list()
    ys = dict()

    for numb in numbs:
        x.extend([numb] * reps)

    for size in sizes:
        ys[size] = list()

        for numb in numbs:
            data = gen_data(numb, size)
            timer = timeit.Timer(lambda: asyncio.run(work(host, port, data), debug=True), "gc.enable()")

            print(f"Packet number: {numb}")
            print(f"Packet size: {size} bytes")

            times = timer.repeat(reps, number=1)
            ys[size].extend(times)

            print()

    with open(f"py_data_{name}.json", "w") as file:
        json.dump(dict(x=x, ys=ys, sizes=sizes), file, indent=4)


if __name__ == "__main__":
    main()
