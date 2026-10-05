"""
Simulated battery container (BMS + PCS) exposed as a Modbus TCP server.

This stands in for the field devices inside a container. It is deliberately
"dumb" and insecure like real Modbus: no authentication, no encryption.
That is why it lives on an isolated site network that only the gateway can reach.

Holding register map (scaled integers, as real devices do):
  0  SoC                %      x10   uint16
  1  DC voltage         V      x10   uint16
  2  DC current         A      x10   int16
  3  Active power       kW     x10   int16   (+ discharge / - charge)
  4  Max cell temp      degC   x10   int16
  5  Min cell temp      degC   x10   int16
  6  Alarm bitfield            bit0 over-temp, bit1 low SoC, bit2 high SoC
  7  Operating state           0 idle, 1 charging, 2 discharging, 3 fault
  10 Power setpoint     kW     x10   int16   (WRITABLE by the gateway)
  11 Heartbeat counter                uint16
"""
import argparse
import asyncio
import logging
import random

from pymodbus.datastore import (ModbusDeviceContext, ModbusSequentialDataBlock,
                                ModbusServerContext)
from pymodbus.server import StartAsyncTcpServer

log = logging.getLogger("sim")
HR = 3  # function code for holding registers


def u16(v: int) -> int:
    """Encode a signed value as an unsigned 16-bit register."""
    return int(v) & 0xFFFF


def s16(v: int) -> int:
    """Decode an unsigned 16-bit register as signed."""
    return v - 0x10000 if v & 0x8000 else v


class BatteryContainer:
    def __init__(self, capacity_kwh: float, max_power_kw: float, soc: float):
        self.capacity_kwh = capacity_kwh
        self.max_power_kw = max_power_kw  # hard physical limit, enforced locally
        self.soc = soc
        self.power_kw = 0.0
        self.temp = 24.0
        self.heartbeat = 0

    def step(self, setpoint_kw: float, dt: float, time_scale: float):
        # Local safety interlock: the site never exceeds its physical limits,
        # whatever the gateway or the cloud asks for.
        target = max(-self.max_power_kw, min(self.max_power_kw, setpoint_kw))
        if self.soc <= 2.0 and target > 0:
            target = 0.0
        if self.soc >= 98.0 and target < 0:
            target = 0.0
        # Power ramps toward the target (inverters don't jump instantly)
        self.power_kw += (target - self.power_kw) * 0.3
        # Energy balance (time_scale speeds up the slow multi-day chemistry for the demo)
        self.soc -= (self.power_kw * dt * time_scale / 3600.0) / self.capacity_kwh * 100.0
        self.soc = max(0.0, min(100.0, self.soc))
        # Thermal: heats up with throughput, cools toward ambient
        self.temp += (abs(self.power_kw) / self.max_power_kw) * 0.4 - (self.temp - 24.0) * 0.05
        self.heartbeat = (self.heartbeat + 1) & 0xFFFF

    def registers(self) -> list[int]:
        voltage = 760.0 + self.soc * 0.8
        current = self.power_kw * 1000.0 / voltage
        t_max = self.temp + random.uniform(0.5, 1.5)
        t_min = self.temp - random.uniform(0.5, 1.5)
        alarms = (1 if t_max > 45 else 0) | (2 if self.soc < 10 else 0) | (4 if self.soc > 95 else 0)
        state = 0 if abs(self.power_kw) < 1 else (2 if self.power_kw > 0 else 1)
        return [u16(round(self.soc * 10)), u16(round(voltage * 10)), u16(round(current * 10)),
                u16(round(self.power_kw * 10)), u16(round(t_max * 10)), u16(round(t_min * 10)),
                alarms, state]


async def physics_loop(dev: ModbusDeviceContext, bat: BatteryContainer, time_scale: float):
    while True:
        setpoint = s16(dev.getValues(HR, 10, 1)[0]) / 10.0
        bat.step(setpoint, dt=1.0, time_scale=time_scale)
        dev.setValues(HR, 0, bat.registers())
        dev.setValues(HR, 11, [bat.heartbeat])
        await asyncio.sleep(1.0)


async def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=5020)
    p.add_argument("--capacity-kwh", type=float, default=4000.0)
    p.add_argument("--max-power-kw", type=float, default=500.0)
    p.add_argument("--soc", type=float, default=60.0)
    p.add_argument("--time-scale", type=float, default=60.0,
                   help="simulation speed-up so SoC visibly moves during a demo")
    a = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")

    block = ModbusSequentialDataBlock(0, [0] * 32)
    dev = ModbusDeviceContext(hr=block)
    ctx = ModbusServerContext(devices=dev, single=True)
    bat = BatteryContainer(a.capacity_kwh, a.max_power_kw, a.soc)
    dev.setValues(HR, 0, bat.registers())

    log.info("battery container simulator on %s:%d (capacity %.0f kWh, max %.0f kW)",
             a.host, a.port, a.capacity_kwh, a.max_power_kw)
    asyncio.create_task(physics_loop(dev, bat, a.time_scale))
    await StartAsyncTcpServer(context=ctx, address=(a.host, a.port))


if __name__ == "__main__":
    asyncio.run(main())
