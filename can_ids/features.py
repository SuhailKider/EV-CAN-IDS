"""Streaming feature extraction.

Computes, one frame at a time, the same 12 behavioural features that the
notebook computes in batch with pandas. Every feature only depends on the
current frame and the history of the same CAN ID, so the extractor keeps a
small ring buffer per ID and can run on a live bus.
"""

from __future__ import annotations

import math
from collections import deque
from typing import Deque, Dict, List, Sequence

import numpy as np

from .frame import CANFrame

FEATURE_COLUMNS: List[str] = [
    "delta_time_id",              # Timing patterns
    "rolling_mean_delta_id",      # Expected timing
    "rolling_std_delta_id",       # Timing variance
    "burstiness",                 # DoS indicator
    "id_freq_per_s",              # Message frequency
    "entropy_per_frame",          # Payload randomness
    "rolling_entropy_id",         # Average entropy per ID
    "bit_flip_count",             # Payload changes
    "payload_slope",              # Rate of change
    "payload_stability",          # Variance
    "payload_correlation_score",  # Inter-byte correlation
    "byte_prediction_error_mean", # Deviation from expected
]

FEATURE_LABELS: Dict[str, str] = {
    "delta_time_id": "inter-arrival time",
    "rolling_mean_delta_id": "mean inter-arrival time",
    "rolling_std_delta_id": "timing jitter",
    "burstiness": "burst size (10 ms)",
    "id_freq_per_s": "message frequency",
    "entropy_per_frame": "payload entropy",
    "rolling_entropy_id": "mean payload entropy",
    "bit_flip_count": "bit flips vs. previous",
    "payload_slope": "payload slope",
    "payload_stability": "payload variance",
    "payload_correlation_score": "inter-byte correlation",
    "byte_prediction_error_mean": "sequence prediction error",
}

WINDOW = 20          # rolling window used throughout the notebook
BURST_WINDOW_S = 0.01
PRED_WINDOW = 5      # sequence predictor looks at the previous 5 payloads

_POPCOUNT = [bin(i).count("1") for i in range(256)]


def payload_entropy(payload: Sequence[int]) -> float:
    """Shannon entropy (bits) of the byte-value distribution of one payload."""
    counts: Dict[int, int] = {}
    for b in payload:
        counts[b] = counts.get(b, 0) + 1
    n = len(payload)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _std(values: Sequence[float], ddof: int) -> float:
    n = len(values)
    if n - ddof <= 0:
        return 0.0
    mean = sum(values) / n
    return math.sqrt(sum((v - mean) ** 2 for v in values) / (n - ddof))


class _IdState:
    __slots__ = ("last_ts", "deltas", "timestamps", "entropies", "payloads", "count")

    def __init__(self) -> None:
        self.last_ts: float | None = None
        self.deltas: Deque[float] = deque(maxlen=WINDOW)
        self.timestamps: Deque[float] = deque()
        self.entropies: Deque[float] = deque(maxlen=WINDOW)
        self.payloads: Deque[tuple] = deque(maxlen=WINDOW)
        self.count = 0


class OnlineFeatureExtractor:
    """Per-CAN-ID stateful feature extractor.

    ``extract`` must be called with frames in timestamp order.
    """

    def __init__(self) -> None:
        self._state: Dict[int, _IdState] = {}

    def reset(self) -> None:
        self._state.clear()

    @property
    def seen_ids(self) -> int:
        return len(self._state)

    def extract(self, frame: CANFrame) -> List[float]:
        st = self._state.get(frame.can_id)
        if st is None:
            st = self._state[frame.can_id] = _IdState()
        ts = frame.timestamp
        payload = frame.payload
        st.count += 1

        # --- timing -------------------------------------------------------
        delta = 0.0 if st.last_ts is None else ts - st.last_ts
        st.last_ts = ts
        st.deltas.append(delta)
        deltas = st.deltas
        rolling_mean_delta = sum(deltas) / len(deltas)
        rolling_std_delta = _std(deltas, ddof=1)  # pandas default

        # burstiness: messages of this ID within the last 10 ms
        tss = st.timestamps
        tss.append(ts)
        while ts - tss[0] > BURST_WINDOW_S:
            tss.popleft()
        burstiness = float(len(tss))

        # frequency over the rolling window of the last WINDOW timestamps
        n_window = min(st.count, WINDOW)
        span = sum(list(deltas)[-(n_window - 1):]) if n_window > 1 else 0.0
        id_freq = n_window / (span if span > 0 else 1e-9)

        # --- payload ------------------------------------------------------
        ent = payload_entropy(payload)
        st.entropies.append(ent)
        rolling_entropy = sum(st.entropies) / len(st.entropies)

        prev_payloads = st.payloads
        if prev_payloads:
            prev = prev_payloads[-1]
            bit_flips = float(sum(_POPCOUNT[a ^ b] for a, b in zip(payload, prev)))
            slope = sum(abs(a - b) for a, b in zip(payload, prev)) / 8.0
            recent = list(prev_payloads)[-PRED_WINDOW:]
            k = len(recent)
            pred_err = sum(
                abs(payload[i] - sum(p[i] for p in recent) / k) for i in range(8)
            ) / 8.0
        else:
            bit_flips = slope = pred_err = 0.0
        prev_payloads.append(payload)

        stability = 0.0
        corr = 0.0
        if len(prev_payloads) >= 2:
            block = np.asarray(prev_payloads, dtype=float)
            if len(prev_payloads) >= WINDOW:
                stability = float(block.std(axis=0).mean())
            corr = _mean_abs_offdiag_corr(block)

        return [
            delta,
            rolling_mean_delta,
            rolling_std_delta,
            burstiness,
            id_freq,
            ent,
            rolling_entropy,
            bit_flips,
            slope,
            stability,
            corr,
            pred_err,
        ]

    def extract_many(self, frames: Sequence[CANFrame]) -> np.ndarray:
        if not frames:
            return np.zeros((0, len(FEATURE_COLUMNS)))
        return np.asarray([self.extract(f) for f in frames], dtype=float)


def _mean_abs_offdiag_corr(block: np.ndarray) -> float:
    """Mean |Pearson r| between byte columns, ignoring constant columns.

    Equivalent to ``np.nanmean(np.abs(np.corrcoef(block, rowvar=False)[mask]))``
    in the notebook, without the RuntimeWarnings.
    """
    centered = block - block.mean(axis=0)
    norms = np.sqrt((centered ** 2).sum(axis=0))
    live = norms > 0
    if live.sum() < 2:
        return 0.0
    c = centered[:, live] / norms[live]
    r = np.abs(c.T @ c)
    m = r.shape[0]
    return float((r.sum() - np.trace(r)) / (m * m - m))
