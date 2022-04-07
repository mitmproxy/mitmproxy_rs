import asyncio

import mitmproxy_wireguard

print(f"{dir(mitmproxy_wireguard)=}")


async def main():
    print("main")
    server = await mitmproxy_wireguard.start_server("", 51820)
    print(f"{server=}")
    print(f"{server.send()=}")


if __name__ == "__main__":
    asyncio.run(main())
