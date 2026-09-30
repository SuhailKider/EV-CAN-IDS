"""Tests for parsing, features, detection, alerting and the dashboard API."""

from __future__ import annotations

import math

import numpy as np
import pytest

from can_ids.alerts import AlertManager, JsonlSink
from can_ids.engine import DetectionEngine
from can_ids.features import FEATURE_COLUMNS, OnlineFeatureExtractor, payload_entropy
from can_ids.frame import CANFrame, parse_hcrl_line, read_hcrl_file
from can_ids.model import IDSModel, evaluate, train_model
from can_ids.simulator import AttackInjector, ReplaySource, SimulatedBus


@pytest.fixture(scope="module")
def model() -> IDSModel:
    bus = SimulatedBus(seed=1)
    return train_model(bus.generate(30), n_estimators=100, ecu_names=bus.ecu_names())


# ----------------------------------------------------------------- parsing
HCRL = "Timestamp: 1479121434.850202        ID: 0350    000    DLC: 8    05 28 84 66 6d 00 00 a2"


def test_parse_hcrl_line():
    f = parse_hcrl_line(HCRL)
    assert f is not None
    assert f.can_id == 0x350 and f.dlc == 8
    assert f.data == (0x05, 0x28, 0x84, 0x66, 0x6D, 0x00, 0x00, 0xA2)
    assert math.isclose(f.timestamp, 1479121434.850202)


def test_parse_short_payload_is_padded():
    f = parse_hcrl_line("Timestamp: 1.0 ID: 0001 000 DLC: 2 ff 01")
    assert f.payload == (0xFF, 0x01, 0, 0, 0, 0, 0, 0)
    assert parse_hcrl_line("garbage") is None


def test_read_and_replay_hcrl(tmp_path):
    p = tmp_path / "log.txt"
    p.write_text("\n".join(
        f"Timestamp: {100 + i * 0.01:.6f} ID: 0{0x100 + i % 3:03x} 000 DLC: 8 00 11 22 33 44 55 66 {i:02x}"
        for i in range(50)))
    assert len(list(read_hcrl_file(p, limit=10))) == 10
    src = ReplaySource(p, label=0, loop=False)
    frames = src.frames_until(0.2)
    assert frames[0].timestamp == 0.0  # re-based
    assert all(f.timestamp <= 0.2 for f in frames)
    rest = src.frames_until(10)
    assert len(frames) + len(rest) == 50 and src.exhausted


# ---------------------------------------------------------------- features
def test_entropy():
    assert payload_entropy([0] * 8) == 0.0
    assert payload_entropy(list(range(8))) == pytest.approx(3.0)


def test_features_match_notebook_definitions():
    fx = OnlineFeatureExtractor()
    frames = [CANFrame(i * 0.01, 0x10, 8, (i, 0, 0, 0, 0, 0, 0, 255)) for i in range(25)]
    X = fx.extract_many(frames)
    assert X.shape == (25, len(FEATURE_COLUMNS))
    col = {c: i for i, c in enumerate(FEATURE_COLUMNS)}
    # first frame of an ID: delta 0 and the notebook's 1e-9 span artefact
    assert X[0, col["delta_time_id"]] == 0.0
    assert X[0, col["id_freq_per_s"]] == pytest.approx(1e9)
    assert X[5, col["delta_time_id"]] == pytest.approx(0.01)
    assert X[24, col["id_freq_per_s"]] == pytest.approx(20 / 0.19)
    assert X[1, col["bit_flip_count"]] == 1  # 0 -> 1
    assert X[3, col["bit_flip_count"]] == 1  # 0b010 -> 0b011
    assert X[4, col["bit_flip_count"]] == 3  # 0b011 -> 0b100
    assert X[3, col["payload_slope"]] == pytest.approx(1 / 8)
    # payload_stability only once 20 payloads are buffered
    assert X[18, col["payload_stability"]] == 0.0
    assert X[19, col["payload_stability"]] > 0.0
    # sequence prediction: mean of previous 5 payloads
    assert X[10, col["byte_prediction_error_mean"]] == pytest.approx(abs(10 - np.mean([5, 6, 7, 8, 9])) / 8)


def test_correlation_ignores_constant_columns():
    fx = OnlineFeatureExtractor()
    frames = [CANFrame(i * 0.01, 1, 8, (i, 2 * i, 0, 0, 0, 0, 0, 0)) for i in range(5)]
    X = fx.extract_many(frames)
    assert X[-1, FEATURE_COLUMNS.index("payload_correlation_score")] == pytest.approx(1.0)
    assert not np.isnan(X).any()


# --------------------------------------------------------------- simulator
def test_simulator_is_deterministic_and_periodic():
    a = SimulatedBus(seed=3).generate(2)
    b = SimulatedBus(seed=3).generate(2)
    assert [(f.timestamp, f.can_id, f.data) for f in a] == [(f.timestamp, f.can_id, f.data) for f in b]
    ts = [f.timestamp for f in a]
    assert ts == sorted(ts)
    n_inverter = sum(f.can_id == 0x0B4 for f in a)
    assert 190 <= n_inverter <= 210  # 10 ms period over 2 s


@pytest.mark.parametrize("kind", ["dos", "fuzzy", "impersonation"])
def test_attack_injection_labels(kind):
    inj = AttackInjector(SimulatedBus(seed=5))
    inj.launch(kind, duration=1.0, start=0.5)
    frames = inj.frames_until(2.0)
    attack = [f for f in frames if f.label == 1]
    assert attack and all(f.attack == kind and 0.5 <= f.timestamp < 1.5 for f in attack)
    assert [f.timestamp for f in frames] == sorted(f.timestamp for f in frames)
    if kind == "dos":
        assert {f.can_id for f in attack} == {0}


# ------------------------------------------------------------------- model
def test_model_detects_all_attack_types(model):
    inj = AttackInjector(SimulatedBus(seed=77))
    for i, kind in enumerate(("dos", "fuzzy", "impersonation")):
        inj.launch(kind, duration=3, start=2 + i * 6)
    res = evaluate(model, inj.frames_until(20))
    hy, ml = res["hybrid"], res["ml"]
    for kind in ("dos", "fuzzy", "impersonation"):
        assert hy["per_attack"][kind]["recall"] > 0.95, kind
    assert hy["recall"] >= ml["recall"]
    assert hy["false_positive_rate"] < 0.08


def test_calibrated_threshold_controls_fpr(model):
    res = evaluate(model, SimulatedBus(seed=11).generate(10))["ml"]
    assert res["attack_samples"] == 0
    assert res["false_positive_rate"] < 0.05


def test_rules_and_classification(model):
    fx = OnlineFeatureExtractor()
    dos = [CANFrame(i * 0.001, 0x000, 8, (0,) * 8) for i in range(20)]
    X = fx.extract_many(dos)
    reasons = model.rules(dos[-1], X[-1])
    assert reasons == ["unknown_id"]
    assert model.classify(dos[-1], X[-1], reasons) == "DOS"
    expl = model.explain(X[-1], reasons=reasons, can_id=0)
    assert expl[0]["rule"] and len(expl) == 4


def test_save_load_roundtrip(model, tmp_path):
    p = tmp_path / "m.joblib"
    model.save(p)
    m2 = IDSModel.load(p)
    X = OnlineFeatureExtractor().extract_many(SimulatedBus(seed=2).generate(0.5))
    np.testing.assert_allclose(model.score(X), m2.score(X))


# ------------------------------------------------------------------ alerts
def test_alert_manager_opens_updates_and_resolves(tmp_path):
    events = []
    am = AlertManager(window=1.0, resolve_after=2.0)
    am.add_sink(lambda ev, inc: events.append((ev, inc.id, inc.category)))
    log = tmp_path / "alerts.jsonl"
    am.add_sink(JsonlSink(log))
    for i in range(3):  # below min_hits: no incident
        am.observe(i * 0.01, 0, "DOS", 0.7, explain=list)
    assert not events
    for i in range(3, 600):
        am.observe(i * 0.001, 0, "DOS", 0.7, explain=list)
    assert events[0] == ("opened", 1, "DOS")
    assert ("escalated", 1, "DOS") not in events  # already CRITICAL
    assert len(am.active()) == 1
    am.tick(0.6 + 2.5)
    assert events[-1] == ("resolved", 1, "DOS")
    assert not am.active()
    assert log.read_text().count("\n") == 2
    assert am.acknowledge(1) and not am.acknowledge(99)
    csv = am.to_csv()
    assert csv.splitlines()[0].startswith("id,status,severity")


def test_isolated_false_positives_do_not_alert():
    am = AlertManager()
    for i in range(20):  # one anomaly per second
        am.observe(float(i), 0x0A0, "ANOMALY", 0.66, explain=list)
        am.tick(float(i))
    assert not am.history


def test_impersonation_incidents_are_per_id():
    am = AlertManager()
    for i in range(10):
        am.observe(i * 0.01, 0x0B4, "IMPERSONATION", 0.7, explain=list, ecu="Motor inverter")
        am.observe(i * 0.01, 0x0A0, "IMPERSONATION", 0.7, explain=list)
    keys = sorted(i.key for i in am.active())
    assert keys == ["0x0A0", "0x0B4"]
    assert {i.ecu for i in am.active()} == {"Motor inverter", None}


# ------------------------------------------------------------------ engine
def test_engine_end_to_end(model):
    eng = DetectionEngine(model, SimulatedBus(seed=21))
    eng.run_offline(3)
    assert eng.status() == "SECURE"
    eng.launch_attack("dos", duration=2)
    eng.run_offline(1)
    assert eng.status() == "UNDER ATTACK"
    snap = eng.snapshot()
    inc = snap["incidents"][0]
    assert inc["category"] == "DOS" and inc["status"] == "ACTIVE"
    assert snap["kpi"]["fps"] > 900  # 2 s average: ~700 normal + 1 s of 1 kHz flood
    assert snap["metrics"]["per_attack"]["dos"]["recall"] > 0.95
    eng.run_offline(6)
    assert eng.status() == "SECURE"
    assert eng.snapshot()["incidents"][0]["status"] == "RESOLVED"


def test_ml_only_mode_misses_dos(model):
    eng = DetectionEngine(model, SimulatedBus(seed=22))
    eng.set_mode("ml")
    eng.launch_attack("dos", duration=2)
    eng.run_offline(2)
    assert eng.metrics()["per_attack"]["dos"]["recall"] < 0.5


# --------------------------------------------------------------- dashboard
def test_dashboard_api(model):
    from can_ids.dashboard import create_app

    eng = DetectionEngine(model, SimulatedBus(seed=23))
    client = create_app(eng).test_client()
    assert b"EV CAN Bus IDS" in client.get("/").data
    assert client.post("/api/attack", json={"kind": "nope"}).status_code == 400
    r = client.post("/api/attack", json={"kind": "impersonation", "duration": 2, "target": "0x0A0"})
    assert r.status_code == 200 and r.get_json()["attack"]["target"] == "0x0A0"
    eng.run_offline(1.5)
    state = client.get("/api/state").get_json()
    assert state["attacks"] and state["incidents"]
    inc_id = state["incidents"][0]["id"]
    assert client.post(f"/api/incidents/{inc_id}/ack").status_code == 200
    assert client.post("/api/incidents/9999/ack").status_code == 404
    assert client.post("/api/threshold", json={"value": 0.7}).get_json()["threshold"] == 0.7
    assert client.post("/api/control", json={"action": "mode", "value": "ml"}).status_code == 200
    assert eng.mode == "ml"
    assert client.post("/api/control", json={"action": "bogus"}).status_code == 400
    assert client.get("/api/incidents.csv").data.startswith(b"id,status")
    assert "metrics" in client.get("/api/report.json").get_json()
