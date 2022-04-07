import asyncio

import mitmproxy_wireguard

print(f"{dir(mitmproxy_wireguard)=}")


async def main():
    server = None
    def on_event(event):
        # simple echo server
        print(f"{event=}")
        if isinstance(event, mitmproxy_wireguard.DataReceived):
            server.tcp_send(event.connection_id, event.data)

    print("main")
    server = await mitmproxy_wireguard.start_server("", 51820, on_event)
    print(f"{server=}")
    await asyncio.sleep(3)
    print("dropping")
    del server
    # no more messages
    await asyncio.sleep(3)


if __name__ == "__main__":
    asyncio.run(main(), debug=True)
