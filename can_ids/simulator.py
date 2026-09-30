"""Synthetic EV CAN bus traffic and attack injection.

The simulator lets the IDS and dashboard run without the (multi-GB) HCRL
dataset. It models a set of periodic EV ECUs whose payloads carry counters,
checksums and physical signals driven by a shared vehicle state, and it can
inject the three attack families studied in the project:

* **DoS** - high-priority ID ``0x000`` flooded every millisecond.
* **Fuzzy** - random IDs with random payloads.
* **Impersonation** - forged frames using a legitimate ECU's ID.

All sources work in *bus time* (seconds); the engine decides how fast bus
time advances relative to wall-clock time.
"""

from __future__ import annotations

import heapq
import math
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional

from .frame import CANFrame, read_hcrl_file


# ---------------------------------------------------------------------------
# Vehicle model
# ---------------------------------------------------------------------------

class VehicleState:
    """Very small EV model producing smoothly varying physical signals."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.t = 0.0
        self.speed_kph = 40.0
        self.torque_nm = 50.0
        self.soc = 78.0
        self.pack_v = 392.0
        self.pack_a = 20.0
        self.batt_temp = 31.0
        self.motor_rpm = 3000.0
        self.steer_deg = 0.0
        self.brake = 0.0
        self._phase = rng.uniform(0, 2 * math.pi)

    def advance(self, t: float) -> None:
        dt = max(0.0, t - self.t)
        if dt == 0.0:
            return
        self.t = t
        r = self.rng
        # Gentle drive cycle: accelerate / cruise / brake on a ~40 s period.
        target = 55 + 35 * math.sin(2 * math.pi * t / 40.0 + self._phase)
        self.speed_kph += (target - self.speed_kph) * min(1.0, dt * 0.8) + r.gauss(0, 0.05)
        self.speed_kph = min(max(self.speed_kph, 0.0), 160.0)
        accel = target - self.speed_kph
        self.torque_nm = max(-80.0, min(250.0, 60 + accel * 6 + r.gauss(0, 1.5)))
        self.brake = max(0.0, min(100.0, -accel * 8)) if accel < -1 else 0.0
        self.motor_rpm = self.speed_kph * 95 + r.gauss(0, 5)
        self.pack_a = self.torque_nm * 0.45 + r.gauss(0, 0.8)
        self.pack_v = 400 - (100 - self.soc) * 0.35 - self.pack_a * 0.05
        self.soc = max(5.0, self.soc - max(self.pack_a, 0) * dt * 1e-4)
        self.batt_temp += (30 + abs(self.pack_a) * 0.05 - self.batt_temp) * dt * 0.01
        self.steer_deg = 25 * math.sin(2 * math.pi * t / 13.0) + r.gauss(0, 0.3)


def _u16(v: float) -> tuple:
    x = int(v) & 0xFFFF
    return (x >> 8) & 0xFF, x & 0xFF


def _checksum(data: List[int]) -> int:
    return sum(data) & 0xFF


# ---------------------------------------------------------------------------
# ECU definitions
# ---------------------------------------------------------------------------

@dataclass
class ECU:
    can_id: int
    name: str
    period: float
    encode: Callable[[VehicleState, int], List[int]]
    jitter: float = 0.00015
    dlc: int = 8
    counter: int = 0


def _bms_status(v: VehicleState, c: int) -> List[int]:
    hv, lv = _u16(v.pack_v * 10)
    ha, la = _u16((v.pack_a + 500) * 10)
    d = [hv, lv, ha, la, int(v.soc * 2) & 0xFF, c & 0x0F, 0x00]
    return d + [_checksum(d)]


def _bms_temps(v: VehicleState, c: int) -> List[int]:
    base = int(v.batt_temp + 40)
    return [base, base + 1, base - 1, base, base + 2, 0x00, 0x00, c & 0xFF]


def _inverter(v: VehicleState, c: int) -> List[int]:
    ht, lt = _u16((v.torque_nm + 1000) * 10)
    hr, lr = _u16(v.motor_rpm)
    d = [ht, lt, hr, lr, 0x10, (c & 0x0F) << 4, 0x00]
    return d + [_checksum(d)]


def _vcu_cmd(v: VehicleState, c: int) -> List[int]:
    ht, lt = _u16((v.torque_nm + 1000) * 10)
    d = [ht, lt, 0x01, 0x00, 0x00, 0x00, c & 0x0F]
    return d + [_checksum(d)]


def _wheel_speed(v: VehicleState, c: int) -> List[int]:
    out: List[int] = []
    for k in range(4):
        h, l = _u16(v.speed_kph * 100 + k * 3)
        out += [h, l]
    return out


def _abs(v: VehicleState, c: int) -> List[int]:
    d = [int(v.brake * 2) & 0xFF, 0x00, 0x00, 0x08, 0x00, 0x00, c & 0x0F]
    return d + [_checksum(d)]


def _steering(v: VehicleState, c: int) -> List[int]:
    h, l = _u16((v.steer_deg + 780) * 10)
    d = [h, l, 0x00, 0x00, 0x00, 0x00, c & 0x0F]
    return d + [_checksum(d)]


def _dash(v: VehicleState, c: int) -> List[int]:
    h, l = _u16(v.speed_kph * 100)
    return [h, l, int(v.soc) & 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00]


def _charger(v: VehicleState, c: int) -> List[int]:
    return [0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, c & 0xFF]


def _thermal(v: VehicleState, c: int) -> List[int]:
    t = int(v.batt_temp + 40)
    return [t, t - 2, 0x32, 0x28, 0x00, 0x00, 0x00, 0x00]


def _dcdc(v: VehicleState, c: int) -> List[int]:
    h, l = _u16(13.8 * 100)
    return [h, l, 0x10, 0x00, 0x00, 0x00, 0x00, c & 0x0F]


def _gateway(v: VehicleState, c: int) -> List[int]:
    return [0xA0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, c & 0xFF]


def _body(v: VehicleState, c: int) -> List[int]:
    return [0x00, 0x21, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00]


def _airbag(v: VehicleState, c: int) -> List[int]:
    return [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, c & 0x0F, 0x5A]


def default_ecus() -> List[ECU]:
    """The EV network used by the simulator (IDs chosen to avoid 0x000)."""
    return [
        ECU(0x0A0, "VCU torque command", 0.010, _vcu_cmd),
        ECU(0x0B4, "Motor inverter", 0.010, _inverter),
        ECU(0x0C8, "ABS / ESC", 0.020, _abs),
        ECU(0x0D0, "Wheel speeds", 0.020, _wheel_speed),
        ECU(0x125, "Steering angle", 0.020, _steering),
        ECU(0x164, "BMS pack status", 0.020, _bms_status),
        ECU(0x1F0, "Airbag controller", 0.050, _airbag),
        ECU(0x260, "BMS cell temps", 0.100, _bms_temps),
        ECU(0x2A0, "Thermal management", 0.100, _thermal),
        ECU(0x316, "DC-DC converter", 0.100, _dcdc),
        ECU(0x329, "Instrument cluster", 0.100, _dash),
        ECU(0x3E9, "Body control", 0.200, _body),
        ECU(0x43F, "Gateway heartbeat", 0.500, _gateway),
        ECU(0x545, "On-board charger", 0.500, _charger),
    ]


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

class FrameSource:
    """A time-ordered stream of CAN frames in bus time."""

    name = "source"
    labelled = False

    def frames_until(self, t_end: float) -> List[CANFrame]:  # pragma: no cover
        raise NotImplementedError

    @property
    def exhausted(self) -> bool:
        return False

    def ecu_names(self) -> Dict[int, str]:
        return {}


class SimulatedBus(FrameSource):
    """Normal traffic from :func:`default_ecus` driven by :class:`VehicleState`."""

    name = "simulated EV bus"
    labelled = True

    def __init__(self, seed: int = 7, ecus: Optional[List[ECU]] = None) -> None:
        self.rng = random.Random(seed)
        self.vehicle = VehicleState(self.rng)
        self.ecus = ecus or default_ecus()
        self._heap: List[tuple] = []
        for i, ecu in enumerate(self.ecus):
            heapq.heappush(self._heap, (self.rng.uniform(0, ecu.period), i))

    def ecu_names(self) -> Dict[int, str]:
        return {e.can_id: e.name for e in self.ecus}

    def frames_until(self, t_end: float) -> List[CANFrame]:
        out: List[CANFrame] = []
        heap = self._heap
        while heap and heap[0][0] <= t_end:
            t, i = heapq.heappop(heap)
            ecu = self.ecus[i]
            self.vehicle.advance(t)
            data = [b & 0xFF for b in ecu.encode(self.vehicle, ecu.counter)]
            ecu.counter += 1
            out.append(CANFrame(t, ecu.can_id, ecu.dlc, tuple(data), label=0))
            nxt = t + ecu.period + self.rng.gauss(0, ecu.jitter)
            heapq.heappush(heap, (max(nxt, t + 1e-5), i))
        return out

    def generate(self, duration: float) -> List[CANFrame]:
        """Convenience: all frames in ``[0, duration]``."""
        return self.frames_until(duration)


class ReplaySource(FrameSource):
    """Replays an HCRL ``.txt`` log, re-based so that bus time starts at 0."""

    labelled = False

    def __init__(self, path: str | Path, label: Optional[int] = None, loop: bool = True) -> None:
        self.path = Path(path)
        self.name = f"replay: {self.path.name}"
        self.label = label
        self.labelled = label is not None
        self.loop = loop
        self._offset = 0.0
        self._t0: Optional[float] = None
        self._last = 0.0
        self._it = self._open()
        self._pending: Optional[CANFrame] = None
        self._done = False

    def _open(self) -> Iterator[CANFrame]:
        return read_hcrl_file(self.path, label=self.label)

    @property
    def exhausted(self) -> bool:
        return self._done

    def _next(self) -> Optional[CANFrame]:
        while True:
            try:
                f = next(self._it)
            except StopIteration:
                if not self.loop:
                    self._done = True
                    return None
                self._it = self._open()
                self._offset = self._last + 0.01
                self._t0 = None
                continue
            if self._t0 is None:
                self._t0 = f.timestamp
            f.timestamp = f.timestamp - self._t0 + self._offset
            self._last = f.timestamp
            return f

    def frames_until(self, t_end: float) -> List[CANFrame]:
        out: List[CANFrame] = []
        while True:
            f = self._pending or self._next()
            self._pending = None
            if f is None:
                break
            if f.timestamp > t_end:
                self._pending = f
                break
            out.append(f)
        return out


# ---------------------------------------------------------------------------
# Attacks
# ---------------------------------------------------------------------------

ATTACK_TYPES = ("dos", "fuzzy", "impersonation")


@dataclass
class ActiveAttack:
    kind: str
    start: float
    end: float
    target_id: Optional[int] = None
    rate_hz: float = 0.0
    next_t: float = 0.0
    sent: int = 0
    params: dict = field(default_factory=dict)

    def as_dict(self, now: float) -> dict:
        return {
            "kind": self.kind,
            "target": f"0x{self.target_id:03X}" if self.target_id is not None else None,
            "remaining": max(0.0, round(self.end - now, 1)),
            "sent": self.sent,
            "rate_hz": self.rate_hz,
        }


class AttackInjector(FrameSource):
    """Wraps another source and merges injected attack frames into it."""

    DEFAULT_RATES = {"dos": 1000.0, "fuzzy": 400.0, "impersonation": 100.0}

    def __init__(self, base: FrameSource, seed: int = 1337) -> None:
        self.base = base
        self.name = base.name
        self.labelled = base.labelled
        self.rng = random.Random(seed)
        self.attacks: List[ActiveAttack] = []
        self.now = 0.0

    def ecu_names(self) -> Dict[int, str]:
        return self.base.ecu_names()

    @property
    def exhausted(self) -> bool:
        return self.base.exhausted

    def launch(self, kind: str, duration: float = 8.0, start: Optional[float] = None,
               target_id: Optional[int] = None, rate_hz: Optional[float] = None) -> ActiveAttack:
        if kind not in ATTACK_TYPES:
            raise ValueError(f"unknown attack {kind!r}; expected one of {ATTACK_TYPES}")
        start = self.now if start is None else start
        if kind == "impersonation" and target_id is None:
            target_id = 0x0B4  # motor inverter
        if kind == "dos":
            target_id = 0x000
        atk = ActiveAttack(kind, start, start + duration, target_id,
                           rate_hz or self.DEFAULT_RATES[kind], next_t=start)
        self.attacks.append(atk)
        return atk

    def stop_all(self) -> None:
        for a in self.attacks:
            a.end = min(a.end, self.now)

    def active(self) -> List[ActiveAttack]:
        return [a for a in self.attacks if a.start <= self.now < a.end]

    def _payload(self, atk: ActiveAttack) -> tuple:
        r = self.rng
        if atk.kind == "dos":
            return (0,) * 8
        if atk.kind == "fuzzy":
            return tuple(r.randrange(256) for _ in range(8))
        # Impersonation: forge a max-torque / max-rpm command on the target ID.
        c = atk.sent
        d = [0x2E, 0xE0, 0x3A, 0x98, 0x10, (c & 0x0F) << 4, r.randrange(256)]
        return tuple(d + [_checksum(d)])

    def frames_until(self, t_end: float) -> List[CANFrame]:
        frames = self.base.frames_until(t_end)
        injected: List[CANFrame] = []
        for atk in self.attacks:
            stop = min(t_end, atk.end)
            period = 1.0 / atk.rate_hz
            while atk.next_t <= stop and atk.next_t < atk.end:
                t = atk.next_t
                cid = atk.target_id if atk.kind != "fuzzy" else self.rng.randrange(0x800)
                injected.append(CANFrame(t, cid, 8, self._payload(atk), label=1, attack=atk.kind))
                atk.sent += 1
                jitter = self.rng.uniform(-0.1, 0.1) * period if atk.kind != "dos" else 0.0
                atk.next_t = t + period + jitter
        self.now = t_end
        self.attacks = [a for a in self.attacks if a.end > t_end - 60]
        if injected:
            frames = sorted(frames + injected, key=lambda f: f.timestamp)
        return frames
