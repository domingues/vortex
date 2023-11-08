#!/usr/bin/env python3
import asyncio
from collections import deque
from datetime import datetime, timezone

import websockets

CLIENTS = set()
MESSAGE_HISTORY = deque(maxlen=1024)


async def handler(websocket: websockets.WebSocketServerProtocol):
    CLIENTS.add(websocket)
    try:
        for socket_message in MESSAGE_HISTORY:
            await websocket.send(socket_message)
        while True:
            message = await websocket.recv()
            if len(message) > 1024:
                await websocket.close()
                break
            timestamp = int(datetime.now(timezone.utc).timestamp()).to_bytes(
                6, byteorder="big"
            )
            socket_message = timestamp + message
            MESSAGE_HISTORY.append(socket_message)
            websockets.broadcast(CLIENTS, socket_message)
    except websockets.ConnectionClosed:
        pass
    finally:
        CLIENTS.remove(websocket)


async def main():
    async with websockets.serve(handler, "0.0.0.0", 8080, max_size=1536):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
