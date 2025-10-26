#!/usr/bin/env python3
import asyncio, ssl, websockets

CERT, KEY = "localhost+2.pem", "localhost+2-key.pem"

async def handler(ws):
    print("New:", ws.remote_address, "Origin:", ws.request_headers.get("Origin"))
    try:
        async for msg in ws:
            print("Msg:", msg)
            await ws.send("ok")  # simple ack
    except websockets.ConnectionClosed:
        print("Closed:", ws.remote_address)

async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(CERT, KEY)
    async with websockets.serve(handler, "127.0.0.1", 7879, ssl=ctx):
        print("Listening on wss://localhost:7879"); await asyncio.Future()

asyncio.run(main())
