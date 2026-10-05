"""
Security self-test: runs four attacks against the live broker and shows each one fail.

  1. Connect with no client certificate            -> refused by the TLS handshake
  2. Impersonate gw-site-01 with a forged cert     -> refused (not signed by our CA)
  3. Compromised gw-site-02 spoofs site-01 data    -> dropped by the broker ACL
  4. Compromised gw-site-02 commands site-01       -> dropped by the broker ACL

Usage:  python attack_demo.py   (with the broker running; BROKER_HOST/PORT env as for the gateway)
"""
import json
import os
import ssl
import time

import paho.mqtt.client as mqtt

HOST = os.environ.get("BROKER_HOST", "localhost")
PORT = int(os.environ.get("BROKER_PORT", "8883"))
PKI = os.environ.get("PKI_DIR", os.path.join(os.path.dirname(__file__), "pki", "out"))
P = lambda name: os.path.join(PKI, name)  # noqa: E731


def client(cid: str, cert: str | None, key: str | None) -> mqtt.Client:
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=cid)
    c.tls_set(ca_certs=P("ca.crt"), certfile=cert, keyfile=key,
              cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    return c


def try_connect(title: str, c: mqtt.Client) -> None:
    print(f"\n[{title}]")
    try:
        c.connect(HOST, PORT, keepalive=5)
        c.loop_start()
        time.sleep(1.5)
        ok = c.is_connected()
        c.loop_stop()
        c.disconnect()
        print("  RESULT: connected  <-- this should NOT happen" if ok else "  RESULT: refused by broker  [BLOCKED]")
    except (ssl.SSLError, OSError) as e:
        print(f"  RESULT: TLS handshake failed ({type(e).__name__})  [BLOCKED]")


def main():
    print(f"Attacking broker {HOST}:{PORT}")
    try_connect("1. No client certificate", client("intruder", None, None))
    try_connect("2. Forged 'gw-site-01' certificate from a rogue CA", client("gw-site-01-fake", P("rogue.crt"), P("rogue.key")))

    # Listeners with legitimate identities, to observe whether anything spoofed gets through
    received = {"telemetry": 0, "cmd": 0, "legit": 0}
    cloud = client("audit-cloud", P("cloud-service.crt"), P("cloud-service.key"))
    cloud.on_message = lambda *_: None
    gw1 = client("audit-gw-site-01", P("gw-site-01.crt"), P("gw-site-01.key"))

    def on_cloud(_c, _u, m):
        if json.loads(m.payload).get("spoofed"):
            received["telemetry"] += 1
        else:
            received["legit"] += 1  # positive control: real site-01 data does arrive

    def on_gw1(_c, _u, m):
        if json.loads(m.payload).get("spoofed"):
            received["cmd"] += 1

    cloud.on_message, gw1.on_message = on_cloud, on_gw1
    for c, topic in ((cloud, "bess/gw-site-01/telemetry"), (gw1, "bess/gw-site-01/cmd")):
        c.on_connect = lambda cl, *_a, t=topic: cl.subscribe(t, qos=1)
        c.connect(HOST, PORT)
        c.loop_start()
    time.sleep(1.5)

    print("\n[3. Compromised gw-site-02 publishes fake telemetry as site-01]")
    print("[4. Compromised gw-site-02 sends a command to site-01]")
    evil = client("gw-site-02-evil", P("gw-site-02.crt"), P("gw-site-02.key"))
    evil.connect(HOST, PORT)
    evil.loop_start()
    time.sleep(1)
    for _ in range(5):
        evil.publish("bess/gw-site-01/telemetry", json.dumps({"spoofed": True, "soc_pct": 1.0}), qos=1)
        evil.publish("bess/gw-site-01/cmd", json.dumps({"spoofed": True, "cmd": {"type": "set_power_kw", "value": 500}}), qos=1)
    time.sleep(2)
    print(f"  spoofed telemetry that reached the cloud: {received['telemetry']}  "
          f"{'[BLOCKED]' if received['telemetry'] == 0 else '<-- ACL FAILURE'}")
    print(f"  spoofed commands that reached site-01:    {received['cmd']}  "
          f"{'[BLOCKED]' if received['cmd'] == 0 else '<-- ACL FAILURE'}")
    print(f"  (control) genuine site-01 telemetry received by the same listener: {received['legit']}")
    for c in (evil, cloud, gw1):
        c.loop_stop()
        c.disconnect()
    print("\nFailed TLS handshakes appear in the broker log (.run/broker.log).")


if __name__ == "__main__":
    main()
