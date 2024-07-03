import mitmproxy_rs
import asyncio
import socket

async def main():
    resolver = mitmproxy_rs.DnsResolver(use_hosts_file=False, name_servers=['8.8.8.8'])

    async def lookup(host: str):
        try:
            r = await resolver.lookup_ip(host)
        except socket.gaierror as e:
            print(f"{host=} {e=}")
        else:
            print(f"{host=} {r=}")

    await lookup("example.com.")
    await lookup("nxdomain.mitmproxy.org.")
    await lookup("no-a-records.mitmproxy.org.")

    print(f"{mitmproxy_rs.get_system_dns_servers()=}")


asyncio.run(main())
