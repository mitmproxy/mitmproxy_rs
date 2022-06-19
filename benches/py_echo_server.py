import asyncio
import logging
import signal
import sys
import time


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
    server = await asyncio.start_server(handle_connection, "0.0.0.0", 51820)

    def stop(*_):
        server.close()
        signal.signal(signal.SIGINT, lambda *_: sys.exit())

    signal.signal(signal.SIGINT, stop)

    await server.wait_closed()


async def handle_connection(r: asyncio.StreamReader, w: asyncio.StreamWriter):
    logger.debug(f"Connection established: {r} / {w}")

    while True:
        data = await r.read(4096)

        # check if the connection was closed
        if len(data) == 0:
            break

        w.write(data)
        await w.drain()

    w.close()
    logger.debug(f"Connection closed: {r} / {w}")


if __name__ == "__main__":
    asyncio.run(main(), debug=True)
