"""
Cloud side: a minimal fleet service.

  - Connects to the broker with its OWN client certificate (identity: cloud-service).
  - Ingests telemetry, status, events and command acknowledgements for every site.
  - Signs every command with an Ed25519 key, so gateways can verify a command really
    came from the cloud even if the broker itself were compromised.
  - Serves a small dashboard + JSON API.

Demo-only: the "variant" field deliberately produces bad commands (out of range,
expired, forged signature, not allow-listed) to show the gateway refusing them.
"""
import base64
import bisect
import json
import logging
import os
import ssl
import threading
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

log = logging.getLogger("cloud")
E = os.environ.get
BROKER_HOST = E("BROKER_HOST", "localhost")
BROKER_PORT = int(E("BROKER_PORT", "8883"))
PKI = E("PKI_DIR", os.path.join(os.path.dirname(__file__), "..", "pki", "out"))
HERE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(PKI, "cmd-signing.key"), "rb") as f:
    SIGNING_KEY = load_pem_private_key(f.read(), password=None)

lock = threading.Lock()
sites: dict[str, dict] = {}
events: deque = deque(maxlen=200)


def site(sid: str) -> dict:
    return sites.setdefault(sid, {"site": sid, "online": None, "latest": None, "history": [],
                                  "last_seen": None, "replayed_total": 0})


def add_event(sid: str, kind: str, text: str, level: str = "info"):
    events.appendleft({"ts": time.time(), "site": sid, "kind": kind, "text": text, "level": level})


def on_connect(client, _ud, _flags, rc, _props):
    if rc.is_failure:
        log.error("broker refused cloud-service: %s", rc)
        return
    log.info("cloud-service connected to broker over mutual TLS")
    for t in ("bess/+/telemetry", "bess/+/status", "bess/+/events", "bess/+/cmd/ack"):
        client.subscribe(t, qos=1)


def on_message(_c, _ud, msg):
    try:
        data = json.loads(msg.payload)
    except json.JSONDecodeError:
        return
    sid, kind = msg.topic.split("/")[1], "/".join(msg.topic.split("/")[2:])
    with lock:
        s = site(sid)
        if kind == "telemetry":
            point = {"ts": data["ts"], "soc": data["soc_pct"], "power": data["power_kw"],
                     "temp": data["temp_max_c"], "replayed": data.get("replayed", False)}
            hist = s["history"]
            # replayed data arrives late: insert by timestamp so the gap fills in correctly
            idx = bisect.bisect([p["ts"] for p in hist], point["ts"])
            hist.insert(idx, point)
            del hist[:-900]
            if not s["latest"] or data["ts"] >= s["latest"]["ts"]:
                s["latest"] = data
            s["last_seen"] = time.time()
            if data.get("replayed"):
                s["replayed_total"] += 1
        elif kind == "status":
            if s["online"] is not data.get("online"):
                add_event(sid, "status", "gateway online" if data.get("online") else
                          "gateway OFFLINE (MQTT Last Will)", "info" if data.get("online") else "warn")
            s["online"] = data.get("online")
        elif kind == "events":
            t = data.get("type")
            if t == "buffer_flushed":
                add_event(sid, t, f"link restored: replayed {data['count']} buffered samples "
                                  f"covering ~{data['outage_s']}s, no data lost", "good")
            else:
                add_event(sid, t, t.replace("_", " "), "warn")
        elif kind == "cmd/ack":
            ok = data.get("status") == "accepted"
            text = f"{data.get('type')} {data.get('value') if data.get('value') is not None else ''} -> " \
                   f"{data.get('status', '?').upper()}: {data.get('reason')}"
            if data.get("diagnostics"):
                text += " | " + ", ".join(f"{k}={v}" for k, v in data["diagnostics"].items())
            add_event(sid, "ack", text, "good" if ok else "bad")


mq = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="cloud-service")
mq.tls_set(ca_certs=os.path.join(PKI, "ca.crt"), certfile=os.path.join(PKI, "cloud-service.crt"),
           keyfile=os.path.join(PKI, "cloud-service.key"), cert_reqs=ssl.CERT_REQUIRED,
           tls_version=ssl.PROTOCOL_TLS_CLIENT)
mq.on_connect = on_connect
mq.on_message = on_message
mq.reconnect_delay_set(1, 10)

@asynccontextmanager
async def lifespan(_app):
    mq.connect_async(BROKER_HOST, BROKER_PORT, keepalive=10)
    mq.loop_start()
    yield
    mq.loop_stop()


app = FastAPI(title="BESS fleet demo", lifespan=lifespan)


class CommandIn(BaseModel):
    site: str
    type: str = "set_power_kw"
    value: float | None = None
    variant: str = "valid"  # valid | out_of_range | expired | bad_signature | not_allowed


def sign(cmd: dict, key: Ed25519PrivateKey) -> str:
    body = json.dumps(cmd, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(key.sign(body)).decode()


@app.post("/api/command")
def send_command(c: CommandIn):
    cmd = {"id": str(uuid.uuid4()), "site": c.site, "type": c.type, "value": c.value,
           "issued_at": time.time(), "ttl_s": 30, "issuer": "cloud-service"}
    key = SIGNING_KEY
    if c.variant == "out_of_range":
        cmd["value"] = 9999.0
    elif c.variant == "expired":
        cmd["issued_at"] = time.time() - 120
    elif c.variant == "not_allowed":
        cmd["type"], cmd["value"] = "disable_protection", None
    elif c.variant == "bad_signature":
        key = Ed25519PrivateKey.generate()  # attacker's key, not the cloud's
    elif c.variant != "valid":
        raise HTTPException(400, "unknown variant")
    info = mq.publish(f"bess/{c.site}/cmd", json.dumps({"cmd": cmd, "sig": sign(cmd, key)}), qos=1)
    with lock:
        add_event(c.site, "cmd", f"sent {cmd['type']} {cmd['value'] if cmd['value'] is not None else ''} "
                                 f"[{c.variant}] id={cmd['id'][:8]}")
    return {"id": cmd["id"], "queued": info.rc == mqtt.MQTT_ERR_SUCCESS}


@app.get("/api/state")
def state():
    now = time.time()
    with lock:
        out = []
        for s in sorted(sites.values(), key=lambda x: x["site"]):
            out.append({**s, "history": s["history"][-300:],
                        "stale_s": round(now - s["last_seen"]) if s["last_seen"] else None})
        return {"broker_connected": mq.is_connected(), "sites": out, "events": list(events)[:60]}


@app.get("/")
def index():
    return FileResponse(os.path.join(HERE, "static", "index.html"))


if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    uvicorn.run(app, host=E("HOST", "0.0.0.0"), port=int(E("PORT", "8000")), log_level="warning")
