"""Flask web dashboard with Server-Sent Events for live updates."""

from __future__ import annotations

import json
import time

from flask import Flask, Response, jsonify, render_template, request

from ..engine import DetectionEngine
from ..simulator import ATTACK_TYPES


def create_app(engine: DetectionEngine, push_interval: float = 0.5) -> Flask:
    app = Flask(__name__)
    app.config["ENGINE"] = engine

    @app.get("/")
    def index():
        return render_template("index.html", attacks=ATTACK_TYPES)

    @app.get("/api/state")
    def state():
        return jsonify(engine.snapshot())

    @app.get("/api/stream")
    def stream():
        def gen():
            # Tell EventSource to reconnect quickly if the server restarts.
            yield "retry: 2000\n\n"
            while True:
                yield f"data: {json.dumps(engine.snapshot())}\n\n"
                time.sleep(push_interval)

        headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
        return Response(gen(), mimetype="text/event-stream", headers=headers)

    @app.post("/api/attack")
    def attack():
        body = request.get_json(silent=True) or {}
        kind = str(body.get("kind", "")).lower()
        if kind not in ATTACK_TYPES:
            return jsonify(error=f"kind must be one of {list(ATTACK_TYPES)}"), 400
        try:
            duration = float(body.get("duration", 8))
            target = body.get("target")
            target_id = int(str(target), 16) if target not in (None, "") else None
        except ValueError:
            return jsonify(error="invalid duration or target"), 400
        atk = engine.launch_attack(kind, duration=max(1.0, min(duration, 120.0)),
                                   target_id=target_id)
        return jsonify(ok=True, attack=atk.as_dict(engine.bus_time))

    @app.post("/api/attack/stop")
    def attack_stop():
        engine.stop_attacks()
        return jsonify(ok=True)

    @app.post("/api/threshold")
    def threshold():
        body = request.get_json(silent=True) or {}
        if body.get("reset"):
            engine.set_threshold(engine.model.threshold)
        else:
            try:
                engine.set_threshold(float(body["value"]))
            except (KeyError, TypeError, ValueError):
                return jsonify(error="value required"), 400
        return jsonify(ok=True, threshold=engine.threshold)

    @app.post("/api/control")
    def control():
        body = request.get_json(silent=True) or {}
        action = body.get("action")
        if action == "pause":
            engine.paused = True
        elif action == "resume":
            engine.paused = False
        elif action == "speed":
            try:
                engine.speed = max(0.1, min(float(body.get("value", 1)), 5.0))
            except (TypeError, ValueError):
                return jsonify(error="invalid speed"), 400
        elif action == "mode":
            try:
                engine.set_mode(str(body.get("value")))
            except ValueError as e:
                return jsonify(error=str(e)), 400
        elif action == "reset":
            engine.stop_attacks()
            engine.reset_stats()
            engine.log_event("Statistics reset", "info")
        else:
            return jsonify(error="unknown action"), 400
        return jsonify(ok=True)

    @app.post("/api/incidents/<int:incident_id>/ack")
    def ack(incident_id: int):
        if not engine.alerts.acknowledge(incident_id):
            return jsonify(error="not found"), 404
        return jsonify(ok=True)

    @app.post("/api/incidents/ack-all")
    def ack_all():
        return jsonify(ok=True, acknowledged=engine.alerts.acknowledge_all())

    @app.get("/api/incidents.csv")
    def incidents_csv():
        return Response(engine.alerts.to_csv(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=can_ids_incidents.csv"})

    @app.get("/api/report.json")
    def report_json():
        snap = engine.snapshot()
        report = {k: snap[k] for k in ("source", "bus_time", "threshold", "model", "kpi",
                                       "metrics", "incident_counts")}
        report["incidents"] = engine.alerts.snapshot(limit=1000)
        return Response(json.dumps(report, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=can_ids_report.json"})

    return app
