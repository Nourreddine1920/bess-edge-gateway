"""
Simulated WAN link (cellular/fibre uplink) between one gateway and the broker.

It is a plain TCP relay. TLS goes straight through it end to end, so it cannot read or
modify anything: it can only pass bytes or cut the link. Creating the flag file cuts
the link (and drops live connections); deleting it restores the link.

  python wan_link.py --listen 18801 --broker-port 8883 --flag .run/wan-gw-site-01.down
"""
import argparse
import asyncio
import logging
import os

log = logging.getLogger("wan")


async def main():
    p = argparse.ArgumentParser()
    p.add_argument("--listen", type=int, required=True)
    p.add_argument("--broker-host", default="127.0.0.1")
    p.add_argument("--broker-port", type=int, default=8883)
    p.add_argument("--flag", required=True)
    p.add_argument("--name", default="site")
    a = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s wan[" + a.name + "] %(message)s")
    live: set[asyncio.StreamWriter] = set()

    def down() -> bool:
        return os.path.exists(a.flag)

    async def pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter):
        try:
            while data := await r.read(65536):
                w.write(data)
                await w.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            w.close()

    async def on_client(cr: asyncio.StreamReader, cw: asyncio.StreamWriter):
        if down():
            cw.close()
            return
        try:
            br, bw = await asyncio.open_connection(a.broker_host, a.broker_port)
        except OSError:
            cw.close()
            return
        live.update({cw, bw})
        await asyncio.gather(pipe(cr, bw), pipe(br, cw))
        live.difference_update({cw, bw})

    async def watch():
        state = down()
        while True:
            await asyncio.sleep(0.3)
            now = down()
            if now != state:
                log.warning("WAN link %s", "CUT" if now else "RESTORED")
                state = now
            if now:
                for w in list(live):
                    w.close()
                live.clear()

    server = await asyncio.start_server(on_client, "127.0.0.1", a.listen)
    log.info("relay 127.0.0.1:%d -> %s:%d (cut by creating %s)", a.listen, a.broker_host, a.broker_port, a.flag)
    asyncio.create_task(watch())
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
