import mitmproxy_rs
import asyncio
import socket

async def main():
    """
    print(f"{await mitmproxy_rs.getaddrinfo("example.com", mitmproxy_rs.AddressFamily.DualStack)=}")
    print(f"{await mitmproxy_rs.getaddrinfo("example.com", mitmproxy_rs.AddressFamily.Ipv4Only)=}")
    print(f"{await mitmproxy_rs.getaddrinfo("example.com", mitmproxy_rs.AddressFamily.Ipv6Only)=}")
    
    try:
        await mitmproxy_rs.getaddrinfo("example.invalid.", mitmproxy_rs.AddressFamily.DualStack)
    except socket.gaierror as e:
        print(f"{e=}")
    """

    try:
        await mitmproxy_rs.getaddrinfo("ipv6.google.com.", mitmproxy_rs.AddressFamily.Ipv4Only)
    except socket.gaierror as e:
        print(f"{e=}")

    """
    servers = mitmproxy_rs.get_system_dns_servers()
    print(f"{servers=}")
    """


asyncio.run(main())