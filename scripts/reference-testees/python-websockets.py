"""Reference permessage-deflate echo server: Python `websockets`.

Second non-ours peer, on a different runtime and a different deflate binding
than Node's. `max_size=None` is required: Autobahn's 9.x cases send payloads far
past the 1 MiB default, and rejecting them would end the run before 12.x.
"""

import asyncio

from websockets.asyncio.server import serve


async def echo(websocket):
    try:
        async for message in websocket:
            await websocket.send(message)
    except Exception:  # noqa: BLE001 - the suite closes hard on purpose
        pass


async def main():
    async with serve(
        echo, "127.0.0.1", 9002, max_size=None, max_queue=None, compression="deflate"
    ):
        print("python-websockets testee listening on 9002", flush=True)
        await asyncio.Future()


asyncio.run(main())
