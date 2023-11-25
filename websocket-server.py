#!/usr/bin/env python3
import asyncio
import dataclasses
from collections import deque
from datetime import datetime, timezone
from heapq import heapify, heappop, heappush

import aiolimiter
import websockets


@dataclasses.dataclass
class Tenant:
    clients: set[websockets.WebSocketServerProtocol]
    messages: deque[bytes]


class LastUpdatedHeap:
    REMOVED = "<removed>"

    def __init__(self, *, maxlen: int):
        self.heap = []
        self.entry_finder = {}
        self.maxlen = maxlen

    def push(self, key: str, value):
        if key in self.entry_finder:
            entry = self.entry_finder.pop(key)
            entry[1] = LastUpdatedHeap.REMOVED
        entry = [datetime.now(), key, value]
        self.entry_finder[key] = entry
        heappush(self.heap, entry)
        while len(self.entry_finder) > self.maxlen and self.heap:
            _, key, _ = heappop(self.heap)
            if key is not LastUpdatedHeap.REMOVED:
                del self.entry_finder[key]
                break
        if len(self.heap) > self.maxlen * 10:
            self.heap = [
                entry for entry in self.heap if entry[1] is not LastUpdatedHeap.REMOVED
            ]
            heapify(self.heap)

    def setdefault(self, name: str, default):
        if name in self.entry_finder:
            return self.entry_finder[name][2]
        self.push(name, default)
        return default

    def touch(self, name: str):
        self.push(name, self.entry_finder[name][2])


TENANTS = LastUpdatedHeap(maxlen=1024 * 6)


async def handler(websocket: websockets.WebSocketServerProtocol):
    tenant_name = websocket.path.strip("/")
    tenant = TENANTS.setdefault(tenant_name, Tenant(set(), deque(maxlen=1024)))
    tenant.clients.add(websocket)
    client_ip = websocket.request_headers.get(
        "X-Forwarded-For", websocket.remote_address
    )
    print(f"NC: {client_ip} {tenant_name}")
    try:
        for socket_message in tenant.messages:
            await websocket.send(socket_message)
        limiter = aiolimiter.AsyncLimiter(100, 60)
        while True:
            async with limiter:
                message = await websocket.recv()
                print(f"NM: {len(message)} {client_ip} {tenant_name}")
                if len(message) > 1024:
                    await websocket.close()
                    break
                timestamp = int(datetime.now(timezone.utc).timestamp()).to_bytes(
                    6, byteorder="big"
                )
                socket_message = timestamp + message
                tenant.messages.append(socket_message)
                websockets.broadcast(tenant.clients, socket_message)
    except websockets.ConnectionClosed:
        pass
    finally:
        tenant.clients.remove(websocket)
        TENANTS.touch(tenant_name)
        print(f"DC: {client_ip} {tenant_name}")


async def main():
    print("Listening on port 8080")
    async with websockets.serve(handler, "0.0.0.0", 8080, max_size=1536):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
