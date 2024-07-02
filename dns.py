import mitmproxy_rs
import asyncio

async def main():
    resp = await mitmproxy_rs.getaddrinfo("example.com", mitmproxy_rs.AddressFamily.DualStack)
    print(f"{resp=}")


asyncio.run(main())