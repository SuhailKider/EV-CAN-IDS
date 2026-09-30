"""Isolation Forest detector with calibration, attack typing and explanations."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .features import FEATURE_COLUMNS, FEATURE_LABELS, WINDOW, OnlineFeatureExtractor
from .frame import CANFrame

F = {name: i for i, name in enumerate(FEATURE_COLUMNS)}

CATEGORIES = ("DOS", "FUZZY", "IMPERSONATION", "ANOMALY")


@dataclass
class IdBaseline:
    """What normal traffic looks like for one CAN ID (learned from training)."""

    period: float
    period_std: float
    pred_err_p99: float
    bit_flip_p99: float
    pred_err_max: float
    bit_flip_max: float


# Specification rules. Each returns a reason code; the dashboard shows them
# next to the Isolation Forest score so every alert is explainable.
RULE_TEXT = {
    "unknown_id": "CAN ID never seen in normal traffic",
    "rate": "ID transmitting faster than its learned period",
    "payload": "payload jump outside learned bounds",
}


@dataclass
class IDSModel:
    """Trained Isolation Forest plus everything needed to score a live stream.

    Scores are the Isolation Forest anomaly score ``s(x) = 2^(-E[h(x)]/c(n))``
    from Liu et al. (``-score_samples``), which already lies in ``(0, 1)`` and
    does not depend on the test set. (The notebook min-max normalised scores
    over the whole test set, which is impossible on a live stream.)
    """

    forest: IsolationForest
    threshold: float
    target_fpr: float
    train_scores_q: Dict[str, float]
    feature_median: np.ndarray
    feature_scale: np.ndarray
    baselines: Dict[int, IdBaseline]
    n_train: int
    source: str = "simulated"
    ecu_names: Dict[int, str] = field(default_factory=dict)

    # ------------------------------------------------------------------ io
    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path: str | Path) -> "IDSModel":
        model = joblib.load(path)
        if not isinstance(model, IDSModel):
            raise TypeError(f"{path} does not contain an IDSModel")
        return model

    # ------------------------------------------------------------- scoring
    def score(self, X: np.ndarray) -> np.ndarray:
        if len(X) == 0:
            return np.zeros(0)
        return -self.forest.score_samples(np.nan_to_num(X, nan=0.0, posinf=1e9))

    def rules(self, frame: CANFrame, x: Sequence[float], seen: Optional[int] = None) -> List[str]:
        """Specification checks that complement the Isolation Forest.

        An Isolation Forest cannot use a feature that is constant in normal
        traffic (e.g. "is this a known ID?"), and it scores values beyond the
        training range no higher than the most extreme training point. These
        per-ID checks, learned from the same normal traffic, cover both gaps.

        ``seen`` is how many frames of this ID have been observed (including
        this one); the rolling-mean check waits until the window is full.
        """
        base = self.baselines.get(frame.can_id)
        if base is None:
            return ["unknown_id"]
        out: List[str] = []
        delta = x[F["delta_time_id"]]
        mean_delta = x[F["rolling_mean_delta_id"]]
        if base.period > 0 and delta > 0 and (
                delta < 0.3 * base.period
                or (0 < mean_delta < 0.7 * base.period and (seen is None or seen > WINDOW))):
            out.append("rate")
        if (x[F["byte_prediction_error_mean"]] > base.pred_err_max * 1.25 + 2
                or x[F["bit_flip_count"]] > base.bit_flip_max + 4):
            out.append("payload")
        return out

    def classify(self, frame: CANFrame, x: Sequence[float],
                 reasons: Sequence[str] = ()) -> str:
        """Attack typing for a flagged frame."""
        base = self.baselines.get(frame.can_id)
        if "unknown_id" in reasons:
            return "DOS" if (x[F["entropy_per_frame"]] < 1.5 or x[F["burstiness"]] >= 3) else "FUZZY"
        if reasons:
            # A flood runs at several times the ID's rate; an impersonator
            # interleaving with the real ECU roughly doubles it.
            mean_delta = x[F["rolling_mean_delta_id"]]
            if ("rate" in reasons and "payload" not in reasons and base is not None
                    and 0 < mean_delta < 0.3 * base.period):
                return "DOS"
            return "IMPERSONATION"
        if base is None:
            # Unknown ID: floods are repetitive, fuzzing is random.
            if x[F["entropy_per_frame"]] < 1.5 or x[F["burstiness"]] >= 3:
                return "DOS"
            return "FUZZY"
        mean_delta = x[F["rolling_mean_delta_id"]]
        timing_off = x[F["delta_time_id"]] < 0.5 * base.period or (
            mean_delta > 0 and mean_delta < 0.75 * base.period)
        payload_off = (x[F["byte_prediction_error_mean"]] > base.pred_err_p99 * 1.5 + 1
                       or x[F["bit_flip_count"]] > base.bit_flip_p99 * 1.5 + 1)
        if timing_off and 0 < mean_delta < 0.3 * base.period and not payload_off:
            return "DOS"
        if timing_off or payload_off:
            return "IMPERSONATION"
        return "ANOMALY"

    def explain(self, x: Sequence[float], top: int = 3, reasons: Sequence[str] = (),
                can_id: Optional[int] = None) -> List[dict]:
        """Rules that fired, then the features that deviate most (robust z-score)."""
        out: List[dict] = []
        base = self.baselines.get(can_id) if can_id is not None else None
        for r in reasons:
            item = {"feature": r, "label": RULE_TEXT[r], "value": "", "normal": "", "z": None, "rule": True}
            if r == "rate" and base:
                item.update(label="period", value=f"{x[F['rolling_mean_delta_id']] * 1000:.1f} ms",
                            normal=f"{base.period * 1000:.1f} ms")
            elif r == "payload" and base:
                item.update(label="prediction error", value=_fmt(x[F["byte_prediction_error_mean"]]),
                            normal=f"≤ {_fmt(base.pred_err_max)}")
            out.append(item)
        z = (np.asarray(x, dtype=float) - self.feature_median) / self.feature_scale
        order = np.argsort(-np.abs(z))[:top]
        return out + [
            {
                "feature": FEATURE_COLUMNS[i],
                "label": FEATURE_LABELS[FEATURE_COLUMNS[i]],
                "value": _fmt(x[i]),
                "normal": _fmt(self.feature_median[i]),
                "z": round(float(z[i]), 1),
            }
            for i in order
        ]


def _fmt(v: float) -> str:
    v = float(v)
    if v != 0 and (abs(v) >= 1e5 or abs(v) < 1e-3):
        return f"{v:.2e}"
    return f"{v:.3f}".rstrip("0").rstrip(".") if "." in f"{v:.3f}" else str(v)


def extract_features(frames: Iterable[CANFrame]) -> tuple[np.ndarray, List[CANFrame]]:
    fx = OnlineFeatureExtractor()
    frames = list(frames)
    return fx.extract_many(frames), frames


def train_model(frames: Iterable[CANFrame], *, n_estimators: int = 200, target_fpr: float = 0.005,
                max_samples: int | str = "auto", random_state: int = 42,
                source: str = "simulated", ecu_names: Optional[Dict[int, str]] = None) -> IDSModel:
    """Train on normal-only traffic (as in the notebook) and calibrate a threshold.

    The threshold is the ``1 - target_fpr`` quantile of the training scores,
    so roughly ``target_fpr`` of normal frames are flagged.
    """
    X, frames = extract_features(frames)
    if len(X) < 100:
        raise ValueError("need at least 100 normal frames to train")

    forest = IsolationForest(n_estimators=n_estimators, max_samples=max_samples,
                             contamination="auto", random_state=random_state, n_jobs=-1)
    forest.fit(X)
    scores = -forest.score_samples(X)
    threshold = float(np.quantile(scores, 1 - target_fpr))

    med = np.median(X, axis=0)
    q75, q25 = np.percentile(X, [75, 25], axis=0)
    scale = (q75 - q25) / 1.349
    fallback = X.std(axis=0)
    scale = np.where(scale > 1e-9, scale, np.where(fallback > 1e-9, fallback, 1.0))

    ids = np.array([f.can_id for f in frames])
    baselines: Dict[int, IdBaseline] = {}
    for cid in np.unique(ids):
        rows = X[ids == cid]
        deltas = rows[1:, F["delta_time_id"]]
        if len(deltas) == 0:
            continue
        baselines[int(cid)] = IdBaseline(
            period=float(np.median(deltas)),
            period_std=float(deltas.std()),
            pred_err_p99=float(np.percentile(rows[:, F["byte_prediction_error_mean"]], 99)),
            bit_flip_p99=float(np.percentile(rows[:, F["bit_flip_count"]], 99)),
            pred_err_max=float(rows[:, F["byte_prediction_error_mean"]].max()),
            bit_flip_max=float(rows[:, F["bit_flip_count"]].max()),
        )

    qs = {f"p{q}": float(np.percentile(scores, q)) for q in (1, 50, 90, 99, 99.9)}
    return IDSModel(forest=forest, threshold=threshold, target_fpr=target_fpr,
                    train_scores_q=qs, feature_median=med, feature_scale=scale,
                    baselines=baselines, n_train=len(X), source=source,
                    ecu_names=dict(ecu_names or {}))


def _metrics(y: np.ndarray, p: np.ndarray, frames: List[CANFrame], thr: float) -> dict:
    tp = int(((p == 1) & (y == 1)).sum())
    fp = int(((p == 1) & (y == 0)).sum())
    tn = int(((p == 0) & (y == 0)).sum())
    fn = int(((p == 0) & (y == 1)).sum())
    per_attack: Dict[str, dict] = {}
    for f, pred in zip(frames, p):
        if f.attack:
            d = per_attack.setdefault(f.attack, {"total": 0, "detected": 0})
            d["total"] += 1
            d["detected"] += int(pred)
    return {
        "threshold": thr,
        "total_samples": len(frames),
        "attack_samples": int(y.sum()),
        "normal_samples": int((y == 0).sum()),
        "true_positives": tp, "false_positives": fp,
        "true_negatives": tn, "false_negatives": fn,
        "accuracy": (tp + tn) / max(1, len(frames)),
        "recall": tp / max(1, tp + fn),
        "precision": tp / max(1, tp + fp),
        "false_positive_rate": fp / max(1, fp + tn),
        "f1": 2 * tp / max(1, 2 * tp + fp + fn),
        "per_attack": {k: {**v, "recall": v["detected"] / max(1, v["total"])}
                       for k, v in per_attack.items()},
    }


def evaluate(model: IDSModel, frames: Iterable[CANFrame], threshold: Optional[float] = None) -> dict:
    """Frame-level metrics (same metrics as the notebook) for both detectors.

    Returns ``{"ml": ..., "hybrid": ...}``: ``ml`` is the Isolation Forest
    alone, ``hybrid`` also flags frames that break a specification rule.
    """
    X, frames = extract_features(frames)
    y = np.array([f.label or 0 for f in frames])
    thr = model.threshold if threshold is None else threshold
    ml = (model.score(X) >= thr).astype(int)
    seen: Dict[int, int] = {}
    rule = np.zeros(len(frames), dtype=int)
    for i, (f, x) in enumerate(zip(frames, X)):
        seen[f.can_id] = seen.get(f.can_id, 0) + 1
        rule[i] = bool(model.rules(f, x, seen[f.can_id]))
    return {
        "ml": _metrics(y, ml, frames, thr),
        "hybrid": _metrics(y, ml | rule, frames, thr),
    }
