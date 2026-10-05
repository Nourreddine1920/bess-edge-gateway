"""
Edge gateway for one battery container.

  site LAN (Modbus TCP, insecure, isolated)  -->  GATEWAY  -->  cloud (MQTT over mutual TLS)

What it does:
  1. Polls the container's BMS/PCS over Modbus and normalises raw registers into
     engineering units (one clean JSON data model).
  2. Publishes telemetry over MQTT with mutual TLS: the gateway's identity is its
     X.509 certificate, not a password.
  3. Store-and-forward: every sample is written to a local SQLite queue first and
     only deleted once the broker acknowledges it (QoS 1). If the WAN drops for
     hours, nothing is lost; data is replayed in order when the link returns.
  4. Commands from the cloud are treated as untrusted input. Each one must pass:
     Ed25519 signature, target site, allow-listed type, expiry, replay check,
     value range and a state interlock, before anything is written to the device.
  5. Reports online/offline with a retained status + MQTT Last Will, and answers
     remote diagnostics requests.
"""
import base64
import json
import logging
import os
import queue
import sqlite3
import ssl
import threading
import time

import paho.mqtt.client as mqtt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pymodbus.client import ModbusTcpClient

log = logging.getLogger("gateway")

# ---------------------------------------------------------------- configuration
E = os.environ.get
SITE_ID = E("SITE_ID", "gw-site-01")                 # must equal the certificate CN
MODBUS_HOST = E("MODBUS_HOST", "127.0.0.1")
MODBUS_PORT = int(E("MODBUS_PORT", "5020"))
BROKER_HOST = E("BROKER_HOST", "localhost")
BROKER_PORT = int(E("BROKER_PORT", "8883"))
PKI = E("PKI_DIR", os.path.join(os.path.dirname(__file__), "..", "pki", "out"))
CA_FILE = os.path.join(PKI, "ca.crt")
CERT_FILE = os.path.join(PKI, f"{SITE_ID}.crt")
KEY_FILE = os.path.join(PKI, f"{SITE_ID}.key")
CMD_PUBKEY = os.path.join(PKI, "cmd-signing.pub")
BUFFER_DB = E("BUFFER_DB", f"/tmp/{SITE_ID}-buffer.db")
BUFFER_MAX_ROWS = int(E("BUFFER_MAX_ROWS", "100000"))  # bounded: oldest dropped first
POLL_S = float(E("POLL_S", "1.0"))
MAX_POWER_KW = float(E("MAX_POWER_KW", "500"))

ALLOWED_COMMANDS = {"set_power_kw", "get_diagnostics"}  # allow-list, everything else refused
CLOCK_SKEW_S = 5.0
STATES = {0: "idle", 1: "charging", 2: "discharging", 3: "fault"}
ALARMS = {0: "over_temperature", 1: "low_soc", 2: "high_soc"}

T_TELEMETRY = f"bess/{SITE_ID}/telemetry"
T_STATUS = f"bess/{SITE_ID}/status"
T_EVENTS = f"bess/{SITE_ID}/events"
T_CMD = f"bess/{SITE_ID}/cmd"
T_ACK = f"bess/{SITE_ID}/cmd/ack"


def s16(v: int) -> int:
    return v - 0x10000 if v & 0x8000 else v


# ---------------------------------------------------------------- disk buffer
class DiskBuffer:
    """Write-ahead queue: a sample is deleted only after the broker has ACKed it."""

    def __init__(self, path: str, max_rows: int):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS q (id INTEGER PRIMARY KEY, ts REAL, topic TEXT, payload TEXT)")
        self.db.commit()
        self.max_rows = max_rows

    def put(self, ts: float, topic: str, payload: dict):
        self.db.execute("INSERT INTO q (ts, topic, payload) VALUES (?,?,?)", (ts, topic, json.dumps(payload)))
        n = self.count()
        if n > self.max_rows:  # bounded storage: never fill the disk of a field device
            self.db.execute("DELETE FROM q WHERE id IN (SELECT id FROM q ORDER BY id LIMIT ?)", (n - self.max_rows,))
        self.db.commit()

    def oldest(self, n: int):
        return self.db.execute("SELECT id, ts, topic, payload FROM q ORDER BY id LIMIT ?", (n,)).fetchall()

    def delete(self, row_id: int):
        self.db.execute("DELETE FROM q WHERE id=?", (row_id,))
        self.db.commit()

    def count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM q").fetchone()[0]


# ---------------------------------------------------------------- command checks
class CommandGuard:
    """Every command is untrusted until proven otherwise. Returns (ok, reason)."""

    def __init__(self, pubkey_path: str):
        with open(pubkey_path, "rb") as f:
            self.pubkey = load_pem_public_key(f.read())
        self.seen_ids: dict[str, float] = {}

    def check(self, msg: dict, soc: float | None) -> tuple[bool, str]:
        cmd, sig = msg.get("cmd"), msg.get("sig")
        if not isinstance(cmd, dict) or not isinstance(sig, str):
            return False, "malformed message"
        # 1. authenticity: signed by the cloud's command key (end-to-end, even if the broker is compromised)
        try:
            body = json.dumps(cmd, sort_keys=True, separators=(",", ":")).encode()
            self.pubkey.verify(base64.b64decode(sig), body)
        except (InvalidSignature, ValueError):
            return False, "invalid signature"
        # 2. addressed to this site
        if cmd.get("site") != SITE_ID:
            return False, "wrong target site"
        # 3. allow-listed command type
        if cmd.get("type") not in ALLOWED_COMMANDS:
            return False, f"command type '{cmd.get('type')}' not allowed"
        # 4. freshness: a delayed command must never execute late
        now = time.time()
        issued, ttl = float(cmd.get("issued_at", 0)), float(cmd.get("ttl_s", 30))
        if issued > now + CLOCK_SKEW_S or now - issued > ttl:
            return False, f"expired (age {now - issued:.0f}s > ttl {ttl:.0f}s)"
        # 5. replay protection
        self.seen_ids = {k: v for k, v in self.seen_ids.items() if now - v < 3600}
        if cmd.get("id") in self.seen_ids:
            return False, "replayed command id"
        self.seen_ids[cmd["id"]] = now
        # 6. value range + 7. state interlock (only for setpoints)
        if cmd["type"] == "set_power_kw":
            v = cmd.get("value")
            if not isinstance(v, (int, float)) or abs(v) > MAX_POWER_KW:
                return False, f"value {v} kW outside +/-{MAX_POWER_KW:.0f} kW"
            if soc is not None and v > 0 and soc < 5:
                return False, "interlock: SoC too low to discharge"
            if soc is not None and v < 0 and soc > 95:
                return False, "interlock: SoC too high to charge"
        return True, "accepted"


# ---------------------------------------------------------------- gateway
class Gateway:
    def __init__(self):
        self.buffer = DiskBuffer(BUFFER_DB, BUFFER_MAX_ROWS)
        self.guard = CommandGuard(CMD_PUBKEY)
        self.commands: queue.Queue = queue.Queue()
        self.modbus = ModbusTcpClient(MODBUS_HOST, port=MODBUS_PORT, timeout=2)
        self.seq = 0
        self.last_soc: float | None = None
        self.modbus_ok = None
        self.started = time.time()
        self.was_connected = False
        self.mqtt = self._make_mqtt()

    # --- MQTT with mutual TLS
    def _make_mqtt(self) -> mqtt.Client:
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=SITE_ID, clean_session=False)
        c.tls_set(ca_certs=CA_FILE, certfile=CERT_FILE, keyfile=KEY_FILE,
                  cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)
        # broker publishes this for us if we vanish without a clean disconnect
        c.will_set(T_STATUS, json.dumps({"site": SITE_ID, "online": False}), qos=1, retain=True)
        c.reconnect_delay_set(min_delay=1, max_delay=10)
        c.max_queued_messages_set(1000)
        c.on_connect = self._on_connect
        c.on_disconnect = self._on_disconnect
        c.on_message = self._on_message
        return c

    def _on_connect(self, client, _ud, _flags, rc, _props):
        if rc.is_failure:
            log.error("broker refused connection: %s", rc)
            return
        log.info("connected to broker %s:%d over mutual TLS as '%s'", BROKER_HOST, BROKER_PORT, SITE_ID)
        client.subscribe(T_CMD, qos=1)
        client.publish(T_STATUS, json.dumps({"site": SITE_ID, "online": True, "ts": time.time()}), qos=1, retain=True)

    def _on_disconnect(self, _c, _ud, _flags, rc, _props):
        log.warning("link to broker lost (%s): buffering to disk", rc)

    def _on_message(self, _c, _ud, msg):
        try:
            self.commands.put(json.loads(msg.payload))
        except json.JSONDecodeError:
            self.commands.put({})

    # --- Modbus acquisition + normalisation
    def read_container(self) -> dict | None:
        try:
            if not self.modbus.connected:
                self.modbus.connect()
            r = self.modbus.read_holding_registers(0, count=12)
            if r.isError():
                raise IOError(str(r))
        except Exception as e:  # noqa: BLE001 - field I/O can fail in many ways
            if self.modbus_ok is not False:
                log.error("container unreachable over Modbus: %s", e)
                self.event("modbus_unreachable", {"error": str(e)})
            self.modbus_ok = False
            self.modbus.close()
            return None
        if self.modbus_ok is False:
            self.event("modbus_restored", {})
        self.modbus_ok = True
        h = r.registers
        self.seq += 1
        self.last_soc = h[0] / 10
        return {
            "site": SITE_ID, "seq": self.seq, "ts": time.time(),
            "soc_pct": h[0] / 10, "voltage_v": h[1] / 10, "current_a": s16(h[2]) / 10,
            "power_kw": s16(h[3]) / 10, "temp_max_c": s16(h[4]) / 10, "temp_min_c": s16(h[5]) / 10,
            "alarms": [name for bit, name in ALARMS.items() if h[6] >> bit & 1],
            "state": STATES.get(h[7], "unknown"), "setpoint_kw": s16(h[10]) / 10, "heartbeat": h[11],
        }

    # --- store-and-forward
    def event(self, kind: str, data: dict):
        self.buffer.put(time.time(), T_EVENTS, {"site": SITE_ID, "type": kind, "ts": time.time(), **data})

    def flush(self):
        """Send buffered messages oldest-first; delete each only after the broker ACKs it."""
        if not self.mqtt.is_connected():
            return
        backlog = self.buffer.count()
        replay = backlog > 3  # more than a normal tick's worth queued: we are catching up after an outage
        sent, samples, first_ts = 0, 0, None
        while self.mqtt.is_connected():
            rows = self.buffer.oldest(200)
            if not rows:
                break
            for row_id, ts, topic, payload in rows:
                body = json.loads(payload)
                if replay:
                    body["replayed"] = True  # lets the cloud tell late data from live data
                info = self.mqtt.publish(topic, json.dumps(body), qos=1)
                try:
                    info.wait_for_publish(timeout=5)
                except (RuntimeError, ValueError):
                    pass
                if not info.is_published():
                    return  # link dropped mid-flush: keep the rest on disk
                self.buffer.delete(row_id)
                sent += 1
                samples += topic == T_TELEMETRY
                first_ts = first_ts or ts
        if replay and sent >= backlog:
            log.info("replayed %d buffered samples after reconnect, nothing lost", samples)
            self.mqtt.publish(T_EVENTS, json.dumps({
                "site": SITE_ID, "type": "buffer_flushed", "ts": time.time(), "count": samples,
                "outage_s": round(time.time() - first_ts)}), qos=1)

    # --- commands
    def handle_commands(self):
        while not self.commands.empty():
            msg = self.commands.get()
            cmd = msg.get("cmd") if isinstance(msg, dict) else None
            cmd_id = cmd.get("id") if isinstance(cmd, dict) else None
            ok, reason = self.guard.check(msg, self.last_soc)
            ack = {"site": SITE_ID, "id": cmd_id, "ts": time.time(),
                   "type": cmd.get("type") if isinstance(cmd, dict) else None,
                   "value": cmd.get("value") if isinstance(cmd, dict) else None,
                   "status": "accepted" if ok else "rejected", "reason": reason}
            if ok and cmd["type"] == "set_power_kw":
                w = self.modbus.write_register(10, int(round(cmd["value"] * 10)) & 0xFFFF)
                if w.isError():
                    ack.update(status="failed", reason="Modbus write failed")
            elif ok and cmd["type"] == "get_diagnostics":
                ack["diagnostics"] = {
                    "uptime_s": round(time.time() - self.started), "buffer_rows": self.buffer.count(),
                    "modbus_ok": self.modbus_ok, "samples_sent_seq": self.seq,
                    "allowed_commands": sorted(ALLOWED_COMMANDS), "max_power_kw": MAX_POWER_KW}
            (log.info if ok else log.warning)("command %s %s: %s", cmd_id, ack["status"].upper(), reason)
            self.mqtt.publish(T_ACK, json.dumps(ack), qos=1)

    def run(self):
        log.info("gateway %s: Modbus %s:%d -> MQTT/mTLS %s:%d, buffer %s",
                 SITE_ID, MODBUS_HOST, MODBUS_PORT, BROKER_HOST, BROKER_PORT, BUFFER_DB)
        self.mqtt.connect_async(BROKER_HOST, BROKER_PORT, keepalive=10)
        self.mqtt.loop_start()
        last_log = 0.0
        while True:
            t0 = time.time()
            sample = self.read_container()
            if sample:
                self.buffer.put(sample["ts"], T_TELEMETRY, sample)  # write-ahead, always
            self.flush()
            self.handle_commands()
            if not self.mqtt.is_connected() and time.time() - self.started > 3 and time.time() - last_log > 5:
                log.warning("offline: %d messages safely buffered on disk", self.buffer.count())
                last_log = time.time()
            time.sleep(max(0.0, POLL_S - (time.time() - t0)))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s[" + SITE_ID + "] %(levelname)s %(message)s")
    logging.getLogger("pymodbus").setLevel(logging.CRITICAL)
    Gateway().run()
