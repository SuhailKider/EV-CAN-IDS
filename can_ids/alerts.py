"""Alert management: turns per-frame detections into incidents.

A single flagged frame is not an alert. Flagged frames are grouped by
``(category, key)``; an *incident* opens once a group sees ``min_hits``
flagged frames inside a sliding window, is updated while the attack goes on,
and resolves after a quiet period. This keeps the alert feed readable (one
DoS incident rather than thousands of frames) and suppresses isolated false
positives.
"""

from __future__ import annotations

import csv
import io
import itertools
import json
import logging
import queue
import threading
import time
import urllib.request
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Deque, Dict, List, Optional, Tuple

log = logging.getLogger("can_ids.alerts")

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

CATEGORY_INFO = {
    "DOS": {
        "title": "Denial-of-Service flood",
        "severity": "CRITICAL",
        "min_hits": 5,
        "action": "Rate-limit or block the offending ID at the gateway; high-priority "
                  "floods starve safety-critical ECUs of bus time.",
    },
    "FUZZY": {
        "title": "Fuzzing / random injection",
        "severity": "HIGH",
        "min_hits": 5,
        "action": "Isolate the compromised node or diagnostic port; enforce an ID "
                  "whitelist at the gateway.",
    },
    "IMPERSONATION": {
        "title": "ECU impersonation / spoofing",
        "severity": "HIGH",
        # A single fuzzed frame on a known ID disturbs that ID's prediction
        # window for ~5 frames; require more than that to open an incident.
        "min_hits": 8,
        "action": "Treat commands on this ID as untrusted; fall back to a safe state "
                  "and verify the sending ECU (e.g. SecOC message authentication).",
    },
    "ANOMALY": {
        "title": "Anomalous traffic",
        "severity": "MEDIUM",
        "min_hits": 12,
        "action": "Monitor. Correlate with vehicle state; recurring anomalies on the "
                  "same ID warrant investigation.",
    },
}


@dataclass
class Incident:
    id: int
    category: str
    key: str
    title: str
    severity: str
    first_seen: float          # bus time
    last_seen: float
    opened_wall: float         # unix time
    can_ids: List[str] = field(default_factory=list)
    frames: int = 0
    peak_score: float = 0.0
    peak_rate: float = 0.0
    status: str = "ACTIVE"     # ACTIVE | RESOLVED
    acknowledged: bool = False
    explanation: List[dict] = field(default_factory=list)
    action: str = ""
    ecu: Optional[str] = None

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["duration"] = round(self.duration, 2)
        d["peak_score"] = round(self.peak_score, 4)
        d["peak_rate"] = round(self.peak_rate, 1)
        return d


class _Group:
    __slots__ = ("hits", "incident", "ids", "best_x")

    def __init__(self) -> None:
        self.hits: Deque[Tuple[float, float]] = deque()
        self.incident: Optional[Incident] = None
        self.ids: Dict[str, int] = {}
        self.best_x: Optional[tuple] = None


AlertSink = Callable[[str, Incident], None]


class AlertManager:
    """Aggregates flagged frames into incidents and fans them out to sinks.

    Sinks are called with ``(event, incident)`` where ``event`` is
    ``"opened"``, ``"escalated"`` or ``"resolved"``.
    """

    def __init__(self, window: float = 1.0, resolve_after: float = 3.0,
                 history: int = 200, sensitivity: float = 1.0) -> None:
        self.window = window
        self.resolve_after = resolve_after
        self.sensitivity = sensitivity  # scales min_hits (lower = more sensitive)
        self._groups: Dict[Tuple[str, str], _Group] = {}
        self._ids = itertools.count(1)
        self.history: Deque[Incident] = deque(maxlen=history)
        self.sinks: List[AlertSink] = []
        self._lock = threading.RLock()
        self.counts = {c: 0 for c in CATEGORY_INFO}

    def add_sink(self, sink: AlertSink) -> None:
        self.sinks.append(sink)

    def _emit(self, event: str, inc: Incident) -> None:
        for sink in self.sinks:
            try:
                sink(event, inc)
            except Exception:  # a broken sink must never stop detection
                log.exception("alert sink failed")

    @staticmethod
    def group_key(category: str, can_id: int) -> str:
        # Floods and fuzzing hop IDs / share one ID; spoofing is per target ID.
        if category in ("IMPERSONATION", "ANOMALY"):
            return f"0x{can_id:03X}"
        return "bus"

    def observe(self, t: float, can_id: int, category: str, score: float,
                explain: Callable[[], List[dict]], ecu: Optional[str] = None) -> None:
        """Record one flagged frame at bus time ``t``."""
        with self._lock:
            key = self.group_key(category, can_id)
            g = self._groups.get((category, key))
            if g is None:
                g = self._groups[(category, key)] = _Group()
            g.hits.append((t, score))
            while g.hits and t - g.hits[0][0] > self.window:
                g.hits.popleft()
            id_hex = f"0x{can_id:03X}"
            g.ids[id_hex] = g.ids.get(id_hex, 0) + 1
            info = CATEGORY_INFO[category]
            rate = len(g.hits) / self.window
            inc = g.incident
            if inc is None:
                need = max(2, round(info["min_hits"] * self.sensitivity))
                if len(g.hits) < need:
                    return
                inc = Incident(
                    id=next(self._ids), category=category, key=key, title=info["title"],
                    severity=info["severity"], first_seen=g.hits[0][0], last_seen=t,
                    opened_wall=time.time(), frames=len(g.hits),
                    peak_score=max(s for _, s in g.hits), peak_rate=rate,
                    explanation=explain(), action=info["action"],
                    ecu=ecu if key != "bus" else None,
                )
                inc.can_ids = self._top_ids(g)
                g.incident = inc
                self.history.appendleft(inc)
                self.counts[category] += 1
                self._emit("opened", inc)
                return
            inc.last_seen = t
            inc.frames += 1
            inc.peak_rate = max(inc.peak_rate, rate)
            if score > inc.peak_score:
                inc.peak_score = score
            if inc.frames % 50 == 0:
                inc.can_ids = self._top_ids(g)
            new_sev = self._escalate(inc)
            if new_sev != inc.severity:
                inc.severity = new_sev
                self._emit("escalated", inc)

    @staticmethod
    def _top_ids(g: _Group, n: int = 5) -> List[str]:
        return [k for k, _ in sorted(g.ids.items(), key=lambda kv: -kv[1])[:n]]

    @staticmethod
    def _escalate(inc: Incident) -> str:
        sev = SEVERITY_ORDER.index(inc.severity)
        if inc.peak_rate >= 200 or inc.duration >= 10:
            sev = max(sev, SEVERITY_ORDER.index("HIGH"))
        if inc.category != "ANOMALY" and inc.peak_rate >= 500:
            sev = SEVERITY_ORDER.index("CRITICAL")
        return SEVERITY_ORDER[sev]

    def tick(self, now: float) -> None:
        """Resolve incidents that have been quiet for ``resolve_after`` seconds."""
        with self._lock:
            for key, g in list(self._groups.items()):
                while g.hits and now - g.hits[0][0] > self.window:
                    g.hits.popleft()
                inc = g.incident
                if inc and now - inc.last_seen > self.resolve_after:
                    inc.status = "RESOLVED"
                    inc.can_ids = self._top_ids(g)
                    g.incident = None
                    g.ids.clear()
                    self._emit("resolved", inc)
                if g.incident is None and not g.hits:
                    del self._groups[key]

    # ---------------------------------------------------------------- views
    def active(self) -> List[Incident]:
        with self._lock:
            return [i for i in self.history if i.status == "ACTIVE"]

    def acknowledge(self, incident_id: int) -> bool:
        with self._lock:
            for inc in self.history:
                if inc.id == incident_id:
                    inc.acknowledged = True
                    return True
        return False

    def acknowledge_all(self) -> int:
        with self._lock:
            n = 0
            for inc in self.history:
                if not inc.acknowledged:
                    inc.acknowledged = True
                    n += 1
            return n

    def clear(self) -> None:
        with self._lock:
            self._groups.clear()
            self.history.clear()
            self.counts = {c: 0 for c in CATEGORY_INFO}

    def snapshot(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return [i.to_dict() for i in list(self.history)[:limit]]

    def to_csv(self) -> str:
        buf = io.StringIO()
        cols = ["id", "status", "severity", "category", "title", "key", "ecu", "can_ids",
                "first_seen", "last_seen", "duration", "frames", "peak_rate", "peak_score",
                "acknowledged", "action"]
        w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for d in self.snapshot(limit=len(self.history)):
            d["can_ids"] = " ".join(d["can_ids"])
            w.writerow(d)
        return buf.getvalue()


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------

def console_sink(event: str, inc: Incident) -> None:
    where = inc.ecu or ", ".join(inc.can_ids) or inc.key
    log.warning("[%s] %s #%d %s on %s (%d frames, peak %.0f/s, score %.3f)",
                inc.severity, event.upper(), inc.id, inc.title, where,
                inc.frames, inc.peak_rate, inc.peak_score)


class JsonlSink:
    """Appends every alert event to a JSON-lines file (SIEM friendly)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def __call__(self, event: str, inc: Incident) -> None:
        rec = {"event": event, "ts": time.time(), **inc.to_dict()}
        with self._lock, open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")


class WebhookSink:
    """POSTs alerts to a webhook (Slack / Discord / Teams / generic JSON).

    Delivery happens on a background thread so a slow endpoint never blocks
    detection. Only ``opened`` and ``escalated`` events at or above
    ``min_severity`` are sent.
    """

    def __init__(self, url: str, min_severity: str = "HIGH", timeout: float = 5.0) -> None:
        self.url = url
        self.min_level = SEVERITY_ORDER.index(min_severity)
        self.timeout = timeout
        self._q: "queue.Queue[dict]" = queue.Queue(maxsize=100)
        threading.Thread(target=self._worker, daemon=True, name="webhook-sink").start()

    def __call__(self, event: str, inc: Incident) -> None:
        if event == "resolved" or SEVERITY_ORDER.index(inc.severity) < self.min_level:
            return
        where = inc.ecu or ", ".join(inc.can_ids) or inc.key
        text = (f":rotating_light: *[{inc.severity}] {inc.title}* on {where} - "
                f"{inc.frames} malicious frames, peak {inc.peak_rate:.0f} msg/s.\n"
                f"Recommended action: {inc.action}")
        payload = {"text": text, "content": text, "incident": inc.to_dict(), "event": event}
        try:
            self._q.put_nowait(payload)
        except queue.Full:
            log.warning("webhook queue full; dropping alert #%d", inc.id)

    def _worker(self) -> None:
        while True:
            payload = self._q.get()
            req = urllib.request.Request(self.url, data=json.dumps(payload).encode(),
                                         headers={"Content-Type": "application/json"})
            try:
                urllib.request.urlopen(req, timeout=self.timeout).close()
            except Exception as e:  # network errors are logged, not raised
                log.warning("webhook delivery failed: %s", e)
