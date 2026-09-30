"""CAN frame representation and HCRL log parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional, Tuple

_HCRL_LINE = re.compile(
    r"Timestamp:\s+([\d.]+)\s+ID:\s+([0-9a-fA-F]+)\s+\d+\s+DLC:\s+(\d+)\s*(.*)"
)
_HEX_BYTE = re.compile(r"[0-9a-fA-F]{2}")


@dataclass
class CANFrame:
    """A single CAN frame.

    ``label`` is ground truth when known (0 = normal, 1 = attack, None = unknown)
    and ``attack`` names the injected attack, if any. Neither is visible to the
    detector; they are only used to report live detection metrics.
    """

    timestamp: float
    can_id: int
    dlc: int
    data: Tuple[int, ...]
    label: Optional[int] = None
    attack: Optional[str] = None
    # Filled in by the detection engine.
    score: float = field(default=0.0, compare=False)
    flagged: bool = field(default=False, compare=False)
    category: Optional[str] = field(default=None, compare=False)
    detector: Optional[str] = field(default=None, compare=False)

    @property
    def payload(self) -> Tuple[int, ...]:
        """Payload padded to 8 bytes, matching the notebook's parser."""
        d = tuple(self.data[:8])
        return d + (0,) * (8 - len(d))

    @property
    def id_hex(self) -> str:
        return f"0x{self.can_id:03X}"

    @property
    def data_hex(self) -> str:
        return " ".join(f"{b:02X}" for b in self.data[: self.dlc])


def parse_hcrl_line(line: str) -> Optional[CANFrame]:
    """Parse one line of the HCRL CAN intrusion dataset text format.

    Example line::

        Timestamp: 1479121434.850202        ID: 0350    000    DLC: 8    05 28 84 66 6d 00 00 a2
    """
    m = _HCRL_LINE.match(line.strip())
    if not m:
        return None
    dlc = int(m.group(3))
    data = tuple(int(b, 16) for b in _HEX_BYTE.findall(m.group(4))[:8])
    return CANFrame(timestamp=float(m.group(1)), can_id=int(m.group(2), 16), dlc=dlc, data=data)


def read_hcrl_file(path: str | Path, label: Optional[int] = None,
                   limit: Optional[int] = None) -> Iterator[CANFrame]:
    """Yield frames from an HCRL ``.txt`` log, skipping unparseable lines."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        n = 0
        for line in f:
            frame = parse_hcrl_line(line)
            if frame is None:
                continue
            frame.label = label
            yield frame
            n += 1
            if limit and n >= limit:
                return
