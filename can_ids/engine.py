"""Real-time detection engine: source -> features -> model -> alerts -> stats."""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

import numpy as np

from .alerts import AlertManager
from .features import OnlineFeatureExtractor
from .frame import CANFrame
from .model import IDSModel
from .simulator import AttackInjector, FrameSource

log = logging.getLogger("can_ids.engine")

BUCKET_S = 0.5          # timeline resolution (bus time)
TIMELINE_POINTS = 120   # 60 s of history
HIST_BINS = 40


@dataclass
class _Bucket:
    t: float
    frames: int = 0
    flagged: int = 0
    attack: int = 0
    max_score: float = 0.0
    sum_score: float = 0.0
    kinds: Dict[str, int] = field(default_factory=dict)

    def to_list(self) -> list:
        mean = self.sum_score / self.frames if self.frames else 0.0
        kinds = ",".join(sorted(self.kinds))
        return [round(self.t, 2), round(self.frames / BUCKET_S, 1),
                round(self.flagged / BUCKET_S, 1), round(self.max_score, 4),
                round(mean, 4), round(self.attack / BUCKET_S, 1), kinds]


@dataclass
class _IdStats:
    count: int = 0
    flagged: int = 0
    last_score: float = 0.0
    max_score: float = 0.0
    bucket_count: int = 0
    rate: float = 0.0
    last_seen: float = 0.0
    last_data: str = ""


class DetectionEngine:
    """Runs the IDS over a frame source, in real time or as fast as possible."""

    def __init__(self, model: IDSModel, source: FrameSource,
                 alerts: Optional[AlertManager] = None, speed: float = 1.0,
                 tick: float = 0.1) -> None:
        self.model = model
        self.source = source if isinstance(source, AttackInjector) else AttackInjector(source)
        self.alerts = alerts or AlertManager()
        self.threshold = model.threshold
        self.speed = speed
        self.tick_s = tick
        self.paused = False
        self.mode = "hybrid"  # or "ml": Isolation Forest only
        self._lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        names = dict(model.ecu_names)
        names.update(self.source.ecu_names())
        self.ecu_names: Dict[int, str] = names
        self.reset_stats()

    # ------------------------------------------------------------ lifecycle
    def reset_stats(self) -> None:
        with self._lock:
            self.fx = OnlineFeatureExtractor() if not hasattr(self, "fx") else self.fx
            self.bus_time = getattr(self, "bus_time", 0.0)
            self.started_wall = time.time()
            self.total_frames = 0
            self.total_flagged = 0
            self.cm = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
            self.per_attack: Dict[str, Dict[str, int]] = {}
            self.hist_normal = np.zeros(HIST_BINS, dtype=np.int64)
            self.hist_attack = np.zeros(HIST_BINS, dtype=np.int64)
            self.timeline: Deque[_Bucket] = deque(maxlen=TIMELINE_POINTS)
            self._bucket = _Bucket(t=self.bus_time)
            self.ids: Dict[int, _IdStats] = {}
            self.recent: Deque[CANFrame] = deque(maxlen=60)
            self.events: Deque[dict] = deque(maxlen=30)
            self.proc_us_per_frame = 0.0
            self.detector_counts = {"ML": 0, "RULE": 0, "ML+RULE": 0}
            self.alerts.clear()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="ids-engine")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        last = time.perf_counter()
        while not self._stop.is_set():
            now = time.perf_counter()
            dt = now - last
            last = now
            if not self.paused:
                # Cap per-tick advance so a stall never produces a giant batch.
                self.step(min(dt * self.speed, 0.5))
            time.sleep(max(0.0, self.tick_s - (time.perf_counter() - now)))

    # ------------------------------------------------------------ processing
    def step(self, dt: float) -> List[CANFrame]:
        """Advance bus time by ``dt`` seconds and process the new frames."""
        with self._lock:
            target = self.bus_time + dt
            frames = self.source.frames_until(target)
            self.process(frames)
            self.bus_time = target
            self._roll_buckets(target)
            self.alerts.tick(target)
            return frames

    def run_offline(self, duration: float, step: float = 0.1) -> None:
        """Process ``duration`` seconds of bus time as fast as possible."""
        end = self.bus_time + duration
        while self.bus_time < end - 1e-9 and not self.source.exhausted:
            self.step(min(step, end - self.bus_time))

    def process(self, frames: List[CANFrame]) -> None:
        if not frames:
            return
        t0 = time.perf_counter()
        X = self.fx.extract_many(frames)
        scores = self.model.score(X)
        thr = self.threshold
        hybrid = self.mode == "hybrid"
        for frame, x, s in zip(frames, X, scores):
            self._roll_buckets(frame.timestamp)
            s = float(s)
            frame.score = s
            ml_hit = s >= thr
            st = self.ids.get(frame.can_id)
            reasons = self.model.rules(frame, x, (st.count if st else 0) + 1) if hybrid else []
            frame.flagged = ml_hit or bool(reasons)
            if frame.flagged:
                frame.detector = "ML+RULE" if ml_hit and reasons else ("ML" if ml_hit else "RULE")
                self.detector_counts[frame.detector] += 1
            self._account(frame, s)
            if frame.flagged:
                cat = self.model.classify(frame, x, reasons)
                frame.category = cat
                self.alerts.observe(
                    frame.timestamp, frame.can_id, cat, s,
                    explain=lambda x=x, r=tuple(reasons), c=frame.can_id: self.model.explain(
                        x, reasons=r, can_id=c),
                    ecu=self.ecu_names.get(frame.can_id),
                )
            self.recent.append(frame)
        elapsed = time.perf_counter() - t0
        us = elapsed * 1e6 / len(frames)
        self.proc_us_per_frame = us if not self.proc_us_per_frame else (
            0.8 * self.proc_us_per_frame + 0.2 * us)

    def _account(self, f: CANFrame, s: float) -> None:
        self.total_frames += 1
        b = self._bucket
        b.frames += 1
        b.sum_score += s
        b.max_score = max(b.max_score, s)
        st = self.ids.get(f.can_id)
        if st is None:
            st = self.ids[f.can_id] = _IdStats()
        st.count += 1
        st.bucket_count += 1
        st.last_score = s
        st.max_score = max(st.max_score, s)
        st.last_seen = f.timestamp
        st.last_data = f.data_hex
        if f.flagged:
            self.total_flagged += 1
            b.flagged += 1
            st.flagged += 1
        if f.label is not None:
            attack = f.label == 1
            key = ("tp" if f.flagged else "fn") if attack else ("fp" if f.flagged else "tn")
            self.cm[key] += 1
            bin_ = min(HIST_BINS - 1, int(s * HIST_BINS))
            (self.hist_attack if attack else self.hist_normal)[bin_] += 1
            if attack:
                b.attack += 1
                kind = f.attack or "attack"
                b.kinds[kind] = b.kinds.get(kind, 0) + 1
                pa = self.per_attack.setdefault(kind, {"total": 0, "detected": 0})
                pa["total"] += 1
                pa["detected"] += int(f.flagged)

    def _roll_buckets(self, t: float) -> None:
        while t >= self._bucket.t + BUCKET_S:
            done = self._bucket
            self.timeline.append(done)
            for st in self.ids.values():
                st.rate = st.bucket_count / BUCKET_S
                st.bucket_count = 0
            self._bucket = _Bucket(t=done.t + BUCKET_S)

    # ------------------------------------------------------------- controls
    def launch_attack(self, kind: str, duration: float = 8.0, target_id: Optional[int] = None):
        with self._lock:
            atk = self.source.launch(kind, duration=duration, target_id=target_id)
            tgt = f" on 0x{atk.target_id:03X}" if atk.target_id is not None else ""
            self.log_event(f"{kind.upper()} attack launched{tgt} for {duration:.0f}s", "attack")
            return atk

    def stop_attacks(self) -> None:
        with self._lock:
            self.source.stop_all()
            self.log_event("All attacks stopped", "info")

    def set_threshold(self, thr: float) -> None:
        with self._lock:
            self.threshold = float(min(max(thr, 0.3), 0.9))
            self.log_event(f"Threshold set to {self.threshold:.3f}", "info")

    def set_mode(self, mode: str) -> None:
        if mode not in ("hybrid", "ml"):
            raise ValueError("mode must be 'hybrid' or 'ml'")
        with self._lock:
            self.mode = mode
            self.log_event("Detector: " + ("Isolation Forest + rules" if mode == "hybrid"
                                           else "Isolation Forest only"), "info")

    def log_event(self, text: str, kind: str = "info") -> None:
        self.events.appendleft({"t": round(self.bus_time, 2), "wall": time.time(),
                                "text": text, "kind": kind})

    # ------------------------------------------------------------- snapshot
    def status(self) -> str:
        active = self.alerts.active()
        if any(i.severity in ("HIGH", "CRITICAL") for i in active):
            return "UNDER ATTACK"
        if active:
            return "WARNING"
        return "SECURE"

    def metrics(self) -> dict:
        tp, fp, tn, fn = (self.cm[k] for k in ("tp", "fp", "tn", "fn"))
        n = tp + fp + tn + fn
        return {
            **self.cm,
            "labelled": n > 0,
            "accuracy": (tp + tn) / n if n else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "precision": tp / (tp + fp) if tp + fp else None,
            "fpr": fp / (fp + tn) if fp + tn else None,
            "f1": 2 * tp / (2 * tp + fp + fn) if tp else None,
            "per_attack": {k: {**v, "recall": v["detected"] / v["total"] if v["total"] else None}
                           for k, v in self.per_attack.items()},
        }

    def snapshot(self) -> dict:
        with self._lock:
            tl = [b.to_list() for b in self.timeline]
            last = list(self.timeline)[-4:]
            fps = sum(b.frames for b in last) / (BUCKET_S * len(last)) if last else 0.0
            aps = sum(b.flagged for b in last) / (BUCKET_S * len(last)) if last else 0.0
            ids = sorted(self.ids.items(), key=lambda kv: (-kv[1].rate, kv[0]))
            known = self.model.baselines
            id_rows = [{
                "id": f"0x{cid:03X}",
                "name": self.ecu_names.get(cid, "Unknown node" if cid not in known else ""),
                "known": cid in known,
                "count": st.count,
                "rate": round(st.rate, 1),
                "expected_rate": round(1 / known[cid].period, 1) if cid in known and known[cid].period > 0 else None,
                "flagged": st.flagged,
                "last_score": round(st.last_score, 3),
                "max_score": round(st.max_score, 3),
                "active": self.bus_time - st.last_seen < 2.0,
                "data": st.last_data,
            } for cid, st in ids if self.bus_time - st.last_seen < 10.0][:30]
            unknown_ids = sum(1 for cid in self.ids if cid not in known)
            recent = [{
                "t": round(f.timestamp, 4), "id": f.id_hex, "dlc": f.dlc, "data": f.data_hex,
                "score": round(f.score, 3), "flagged": f.flagged, "category": f.category,
                "attack": f.attack, "detector": f.detector,
            } for f in list(self.recent)[-40:]][::-1]
            active_attacks = [a.as_dict(self.bus_time) for a in self.source.active()]
            return {
                "status": self.status(),
                "source": self.source.name,
                "labelled": self.source.labelled,
                "bus_time": round(self.bus_time, 2),
                "uptime": round(time.time() - self.started_wall, 1),
                "speed": self.speed,
                "paused": self.paused,
                "mode": self.mode,
                "detectors": dict(self.detector_counts),
                "threshold": round(self.threshold, 4),
                "model": {
                    "threshold": round(self.model.threshold, 4),
                    "target_fpr": self.model.target_fpr,
                    "n_train": self.model.n_train,
                    "source": self.model.source,
                    "trees": self.model.forest.n_estimators,
                    "known_ids": len(known),
                },
                "kpi": {
                    "fps": round(fps, 1),
                    "flagged_ps": round(aps, 1),
                    "total_frames": self.total_frames,
                    "total_flagged": self.total_flagged,
                    "flag_rate": self.total_flagged / self.total_frames if self.total_frames else 0.0,
                    "active_incidents": len(self.alerts.active()),
                    "incidents_total": len(self.alerts.history),
                    "unique_ids": len(self.ids),
                    "unknown_ids": unknown_ids,
                    "us_per_frame": round(self.proc_us_per_frame, 1),
                    "capacity_fps": round(1e6 / self.proc_us_per_frame) if self.proc_us_per_frame else None,
                },
                "timeline": tl,
                "ids": id_rows,
                "recent": recent,
                "incidents": self.alerts.snapshot(40),
                "incident_counts": dict(self.alerts.counts),
                "metrics": self.metrics(),
                "hist": {"normal": self.hist_normal.tolist(), "attack": self.hist_attack.tolist()},
                "attacks": active_attacks,
                "events": list(self.events)[:15],
            }
