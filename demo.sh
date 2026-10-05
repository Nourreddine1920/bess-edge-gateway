#!/usr/bin/env bash
# One-command demo runner (Linux / WSL2).
#   ./demo.sh start            start broker, 2 containers, 2 gateways, 2 WAN links, cloud
#   ./demo.sh logs             follow gateway + WAN logs (keep this terminal visible)
#   ./demo.sh cut 01           cut site 01's WAN link (gateway starts buffering)
#   ./demo.sh restore 01       restore it (buffer is replayed, gap fills in)
#   ./demo.sh attack           run the security self-test
#   ./demo.sh stop             stop everything
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(pwd)
RUN=$ROOT/.run
PY=${PYTHON:-python3}
MOSQ=${MOSQUITTO:-$(command -v mosquitto || echo /usr/sbin/mosquitto)}

start() {
  [ -x "$MOSQ" ] || { echo "mosquitto not found. Install it: sudo apt install mosquitto (or set MOSQUITTO=/path)"; exit 1; }
  [ -f pki/out/ca.crt ] || bash pki/gen_certs.sh
  stop >/dev/null 2>&1 || true
  mkdir -p "$RUN" && rm -f "$RUN"/*.down "$RUN"/*.db*
  sed -e "s#/mosquitto/certs#$ROOT/pki/out#g" -e "s#/mosquitto/config/acl#$ROOT/broker/acl#" \
      broker/mosquitto.conf > "$RUN/mosquitto.conf"

  bg() { local name=$1; shift; nohup "$@" > "$RUN/$name.log" 2>&1 & echo $! >> "$RUN/pids"; }
  bg broker   "$MOSQ" -c "$RUN/mosquitto.conf"
  bg sim-01   $PY simulator/bess_sim.py --port 5021 --soc 62
  bg sim-02   $PY simulator/bess_sim.py --port 5022 --soc 35 --max-power-kw 400
  bg wan-01   $PY wan_link.py --name gw-site-01 --listen 18801 --flag "$RUN/wan-gw-site-01.down"
  bg wan-02   $PY wan_link.py --name gw-site-02 --listen 18802 --flag "$RUN/wan-gw-site-02.down"
  sleep 1.5
  SITE_ID=gw-site-01 MODBUS_PORT=5021 BROKER_PORT=18801 BUFFER_DB="$RUN/gw-site-01.db" bg gw-01 $PY gateway/gateway.py
  SITE_ID=gw-site-02 MODBUS_PORT=5022 BROKER_PORT=18802 BUFFER_DB="$RUN/gw-site-02.db" MAX_POWER_KW=400 bg gw-02 $PY gateway/gateway.py
  PORT=${PORT:-8000} bg cloud $PY cloud/app.py
  sleep 2
  echo "Demo running. Dashboard: http://localhost:${PORT:-8000}"
  echo "Next: ./demo.sh logs   |   ./demo.sh cut 01   |   ./demo.sh attack   |   ./demo.sh stop"
}

stop() {
  [ -f "$RUN/pids" ] && xargs -r kill < "$RUN/pids" 2>/dev/null || true
  rm -f "$RUN/pids"; echo "stopped"
}

case "${1:-start}" in
  start)   start ;;
  stop)    stop ;;
  logs)    tail -n 5 -F "$RUN"/gw-0*.log "$RUN"/wan-0*.log ;;
  cut)     touch "$RUN/wan-gw-site-${2:?site number, e.g. 01}.down"; echo "WAN cut for gw-site-$2" ;;
  restore) rm -f "$RUN/wan-gw-site-${2:?site number}.down"; echo "WAN restored for gw-site-$2" ;;
  attack)  $PY attack_demo.py ;;
  *) echo "usage: $0 start|logs|cut NN|restore NN|attack|stop"; exit 1 ;;
esac
