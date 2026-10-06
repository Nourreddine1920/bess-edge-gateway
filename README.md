# BESS Edge Gateway: secure edge-to-cloud prototype

A small, working prototype of the communication and security layer between a battery
energy storage container and the cloud. Every claim below is something the demo shows live.

```
 SITE (isolated LAN)                 EDGE GATEWAY                         CLOUD
 ┌───────────────────┐  Modbus TCP  ┌──────────────────────────┐  MQTT    ┌─────────────────────┐
 │ BMS + PCS         │◄────────────►│ poll + normalise         │  over    │ broker (mTLS + ACL) │
 │ (simulator)       │  no auth,    │ disk write-ahead buffer  │◄────────►│ fleet service       │
 │ local safety      │  never on    │ command guard (7 checks) │  mutual  │ signs commands      │
 │ interlocks        │  the WAN     │ Last Will, diagnostics   │  TLS     │ dashboard :8000     │
 └───────────────────┘              └──────────────────────────┘          └─────────────────────┘
```

## Live simulation (no install)

`web/index.html` is a self-contained browser version of the whole pipeline, deployed on Vercel. It uses real Ed25519
signing (WebCrypto) and a port of the 7-check command guard, and adds a price-driven cloud optimizer that compares a
100 h iron-air battery with a 4 h Li-ion reference on the same prices. Press **Guided demo** for a 3-minute scripted tour.
Modbus, TLS, the broker and the battery physics are modelled; the Python stack below is the real implementation.

## What it demonstrates

| Requirement | How the prototype does it |
| --- | --- |
| Industrial protocols | Modbus TCP register map with scaled/signed values, normalised into one JSON model |
| Secure edge-to-cloud | MQTT over **mutual TLS**: every gateway's identity is its X.509 certificate (CN = MQTT username) |
| PKI | Root CA, broker cert, one cert per gateway, cloud cert (`pki/gen_certs.sh`) |
| Least privilege | Broker ACL: a gateway can only publish its own topics and read its own command topic |
| Resilience | Write-ahead SQLite buffer: a sample is deleted only after the broker ACKs it (QoS 1). WAN outages lose nothing; data is replayed in order |
| Safe remote control | Commands are **Ed25519-signed** by the cloud and checked at the edge: signature, target site, allow-list, expiry, replay, range, SoC interlock |
| Defence in depth | The simulated container also clamps power to its physical limit, whatever it is told |
| Remote management | Retained online status + MQTT Last Will, remote `get_diagnostics` command |

## Setup (Linux or WSL2 Ubuntu, about 2 minutes)

```bash
sudo apt install -y mosquitto python3-pip
pip install -r requirements.txt          # add --break-system-packages on recent Ubuntu, or use a venv
./demo.sh start                          # generates the PKI on first run
```
Open http://localhost:8000. Stop everything with `./demo.sh stop`.

If a system Mosquitto service is already using port 8883, stop it first: `sudo systemctl stop mosquitto`.

## 5-minute demo script

Keep two windows side by side: the dashboard, and a terminal running `./demo.sh logs`.

1. **The picture (30 s).** "Two simulated containers speak Modbus on an isolated site network. A gateway per site
   polls them, normalises the data and publishes it over MQTT with mutual TLS. Modbus is never exposed to the WAN."
2. **Remote control (45 s).** Send a 300 kW setpoint on site 01. Power ramps up. "The command was signed by the cloud,
   verified at the edge, then written to the device over Modbus."
3. **Attacks on commands (1 min).** Click *Out of range*, *Expired*, *Forged signature*, *Not allow-listed*.
   Each is rejected with a reason. "The gateway treats every command as untrusted input. An expired command matters:
   after an outage, a queued command must never execute late."
4. **WAN outage (1 min 30 s).** `./demo.sh cut 01`. The broker publishes the Last Will, the card goes offline, the logs
   show samples buffering to disk. Wait 15 to 20 seconds, then `./demo.sh restore 01`. The purple points fill the gap.
   "Nothing was lost: every sample is written to disk first and deleted only after the broker acknowledges it."
5. **Identity attacks (1 min).** `./demo.sh attack`. No certificate and a forged certificate are refused at the TLS
   handshake. A compromised site-02 gateway cannot spoof site-01 data or command site-01: the ACL drops it.
   The control line proves the listener does receive genuine data.

Close with: "In production I'd keep this design and swap the pieces for hardened ones" (next section).

## What changes in production

- **Keys in hardware**: device keys generated in a secure element, TPM or OP-TEE/TrustZone, never exportable;
  zero-touch provisioning at the factory; an offline root CA plus intermediates; short-lived certs with rotation and revocation.
- **Secure boot + OTA**: signed images, A/B partitions, health check and automatic rollback, staged canary rollouts
  (SWUpdate, RAUC or Mender on Yocto).
- **Protocols**: IEC 61850 and IEC 60870-5-104 (with IEC 62351) toward the EMS and grid operator using proven stacks;
  OPC UA where interoperability matters; Sparkplug B for MQTT payload conventions.
- **Cloud**: managed broker (AWS IoT Core / Azure IoT Hub), time-series database, alerting, audit log of every command
  tied to a user.
- **Standards**: IEC 62443 zones and conduits, EU Cyber Resilience Act, NIS2.

## Layout

```
simulator/bess_sim.py   Modbus TCP battery container (BMS + PCS registers, local interlocks)
gateway/gateway.py      edge gateway: acquisition, buffer, mTLS publisher, command guard
cloud/app.py            fleet service + dashboard (FastAPI), signs commands
broker/                 Mosquitto config (mTLS required) and ACL
pki/gen_certs.sh        demo PKI and command-signing key
wan_link.py             simulated WAN uplink you can cut and restore
attack_demo.py          security self-test
demo.sh                 start / logs / cut / restore / attack / stop
```

Register map and simulation details are documented at the top of `simulator/bess_sim.py`.
The simulation is generic BESS behaviour, sped up 60x so state of charge visibly moves during a demo.
