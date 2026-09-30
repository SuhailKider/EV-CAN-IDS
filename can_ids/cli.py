"""Command-line interface: ``python -m can_ids <command>``."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import webbrowser
from pathlib import Path
from typing import Optional

from .alerts import AlertManager, JsonlSink, WebhookSink, console_sink
from .engine import DetectionEngine
from .frame import read_hcrl_file
from .model import IDSModel, evaluate, train_model
from .simulator import AttackInjector, ReplaySource, SimulatedBus

DEFAULT_MODEL = Path("models/ids_model.joblib")
log = logging.getLogger("can_ids")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _train(args) -> IDSModel:
    t0 = time.time()
    if getattr(args, "train_file", None):
        log.info("Training on normal traffic from %s (limit=%s)", args.train_file, args.limit)
        frames = read_hcrl_file(args.train_file, label=0, limit=args.limit)
        model = train_model(frames, n_estimators=args.trees, target_fpr=args.target_fpr,
                            source=Path(args.train_file).name)
    else:
        bus = SimulatedBus(seed=args.seed)
        log.info("Training on %.0f s of simulated normal EV traffic", args.train_seconds)
        model = train_model(bus.generate(args.train_seconds), n_estimators=args.trees,
                            target_fpr=args.target_fpr, source="simulated EV bus",
                            ecu_names=bus.ecu_names())
    log.info("Trained on %s frames in %.1fs; calibrated threshold %.4f",
             f"{model.n_train:,}", time.time() - t0, model.threshold)
    return model


def _load_or_train(args) -> IDSModel:
    path = Path(args.model)
    if path.exists() and not args.retrain:
        model = IDSModel.load(path)
        log.info("Loaded model from %s (%s frames, source: %s)", path, f"{model.n_train:,}", model.source)
        return model
    model = _train(args)
    model.save(path)
    log.info("Saved model to %s", path)
    return model


def _source(args):
    if getattr(args, "replay", None):
        return AttackInjector(ReplaySource(args.replay, label=args.replay_label))
    return AttackInjector(SimulatedBus(seed=args.seed + 1000))


def _alerts(args) -> AlertManager:
    am = AlertManager(sensitivity=args.sensitivity)
    am.add_sink(console_sink)
    if args.alert_log:
        am.add_sink(JsonlSink(args.alert_log))
        log.info("Writing alert events to %s", args.alert_log)
    if args.webhook:
        am.add_sink(WebhookSink(args.webhook, min_severity=args.webhook_min_severity))
        log.info("Forwarding %s+ alerts to webhook", args.webhook_min_severity)
    return am


def _print_metrics(res: dict) -> None:
    ml, hy = res["ml"], res["hybrid"]
    print("\n" + "=" * 64)
    print(f"DETECTION METRICS  (IF threshold {ml['threshold']:.4f}, "
          f"{ml['total_samples']:,} frames: {ml['attack_samples']:,} attack / {ml['normal_samples']:,} normal)")
    print("=" * 64)
    print(f"{'':<22}{'Isolation Forest':>20}{'Hybrid (IF + rules)':>22}")
    for k, label in (("accuracy", "Accuracy"), ("recall", "Recall"), ("precision", "Precision"),
                     ("false_positive_rate", "False-positive rate"), ("f1", "F1")):
        print(f"{label:<22}{ml[k] * 100:>19.2f}%{hy[k] * 100:>21.2f}%")
    for k in ("true_positives", "false_positives", "true_negatives", "false_negatives"):
        print(f"{k.replace('_', ' ').title():<22}{ml[k]:>20,}{hy[k]:>22,}")
    for kind in hy.get("per_attack", {}):
        a, b = ml["per_attack"][kind], hy["per_attack"][kind]
        print(f"  {kind + ' recall':<20}{a['recall'] * 100:>19.1f}%{b['recall'] * 100:>21.1f}%")
    print("=" * 64)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_train(args) -> int:
    model = _train(args)
    model.save(args.model)
    print(json.dumps({"model": str(args.model), "n_train": model.n_train,
                      "threshold": model.threshold, "known_ids": len(model.baselines),
                      "train_score_quantiles": model.train_scores_q}, indent=2))
    return 0


def cmd_evaluate(args) -> int:
    model = _load_or_train(args)
    if args.attack:
        frames = []
        for spec in args.attack:
            kind, _, path = spec.partition("=")
            if not path:
                kind, path = Path(spec).stem, spec
            for f in read_hcrl_file(path, label=1, limit=args.limit):
                f.attack = kind
                frames.append(f)
        if args.normal:
            frames += list(read_hcrl_file(args.normal, label=0, limit=args.limit))
        # Each file is its own capture; evaluate them in timestamp order like the notebook.
        frames.sort(key=lambda f: f.timestamp)
    else:
        inj = AttackInjector(SimulatedBus(seed=args.seed + 2000))
        t = 5.0
        for kind in ("dos", "fuzzy", "impersonation"):
            inj.launch(kind, duration=args.attack_seconds, start=t)
            t += args.attack_seconds + 10
        frames = inj.frames_until(t)
    metrics = evaluate(model, frames, threshold=args.threshold)
    _print_metrics(metrics)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(metrics, indent=2))
        print(f"Metrics written to {args.out}")
    return 0


def cmd_monitor(args) -> int:
    """Headless real-time monitor: alerts go to the console / log / webhook."""
    model = _load_or_train(args)
    engine = DetectionEngine(model, _source(args), alerts=_alerts(args), speed=args.speed)
    if args.demo:
        t = 3.0
        for kind in ("dos", "fuzzy", "impersonation"):
            engine.source.launch(kind, duration=6, start=t)
            t += 15
    engine.start()
    log.info("Monitoring %s - press Ctrl+C to stop", engine.source.name)
    try:
        last_log = time.time()
        while True:
            time.sleep(0.2)
            if args.duration and engine.bus_time >= args.duration:
                break
            if time.time() - last_log < 5:
                continue
            last_log = time.time()
            s = engine.snapshot()
            log.info("status=%s bus=%.0fs frames=%s fps=%.0f flagged/s=%.1f incidents=%d active",
                     s["status"], s["bus_time"], f"{s['kpi']['total_frames']:,}", s["kpi"]["fps"],
                     s["kpi"]["flagged_ps"], s["kpi"]["active_incidents"])
    except KeyboardInterrupt:
        pass
    engine.stop()
    return 0


def cmd_dashboard(args) -> int:
    from .dashboard import create_app

    model = _load_or_train(args)
    engine = DetectionEngine(model, _source(args), alerts=_alerts(args), speed=args.speed)
    engine.log_event(f"Monitoring {engine.source.name}", "info")
    engine.start()
    app = create_app(engine)
    url = f"http://{'localhost' if args.host in ('0.0.0.0', '127.0.0.1') else args.host}:{args.port}"
    log.info("Dashboard running at %s", url)
    if args.open:
        webbrowser.open(url)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app.run(host=args.host, port=args.port, threaded=True, debug=False, use_reloader=False)
    return 0


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="can_ids", description="EV CAN bus intrusion detection system")
    sub = p.add_subparsers(dest="command", required=True)

    def model_opts(sp):
        sp.add_argument("--model", default=str(DEFAULT_MODEL), help="model file (default: %(default)s)")
        sp.add_argument("--retrain", action="store_true", help="retrain even if the model file exists")
        sp.add_argument("--train-file", help="HCRL Attack_free_dataset.txt to train on instead of simulated traffic")
        sp.add_argument("--train-seconds", type=float, default=60.0, help="seconds of simulated traffic to train on")
        sp.add_argument("--limit", type=int, default=None, help="max frames to read per HCRL file")
        sp.add_argument("--trees", type=int, default=200, help="Isolation Forest trees (default: 200)")
        sp.add_argument("--target-fpr", type=float, default=0.005,
                        help="fraction of normal training frames above the threshold (default: 0.005)")
        sp.add_argument("--seed", type=int, default=7)

    def live_opts(sp):
        sp.add_argument("--replay", help="replay an HCRL .txt log instead of the simulator")
        sp.add_argument("--replay-label", type=int, choices=(0, 1), default=None,
                        help="ground-truth label for every replayed frame, if known")
        sp.add_argument("--speed", type=float, default=1.0, help="bus time per wall-clock second")
        sp.add_argument("--sensitivity", type=float, default=1.0,
                        help="scales frames needed to open an incident (lower = more sensitive)")
        sp.add_argument("--alert-log", default="logs/alerts.jsonl", help="JSON-lines alert log ('' to disable)")
        sp.add_argument("--webhook", help="POST HIGH+ alerts to this URL (Slack/Discord/Teams/generic)")
        sp.add_argument("--webhook-min-severity", default="HIGH",
                        choices=("LOW", "MEDIUM", "HIGH", "CRITICAL"))

    sp = sub.add_parser("dashboard", help="run the live web dashboard")
    model_opts(sp); live_opts(sp)
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8050)
    sp.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    sp.set_defaults(func=cmd_dashboard)

    sp = sub.add_parser("monitor", help="headless real-time monitor with console alerts")
    model_opts(sp); live_opts(sp)
    sp.add_argument("--demo", action="store_true", help="inject DoS, fuzzy and impersonation attacks")
    sp.add_argument("--duration", type=float, default=0, help="stop after this much bus time (0 = forever)")
    sp.set_defaults(func=cmd_monitor)

    sp = sub.add_parser("train", help="train and save a model")
    model_opts(sp)
    sp.set_defaults(func=cmd_train)

    sp = sub.add_parser("evaluate", help="evaluate on simulated attacks or HCRL files")
    model_opts(sp)
    sp.add_argument("--attack", action="append",
                    help="HCRL attack file, optionally KIND=PATH (repeatable). Omit to use simulated attacks.")
    sp.add_argument("--normal", help="HCRL normal file to mix into the test set")
    sp.add_argument("--attack-seconds", type=float, default=8.0)
    sp.add_argument("--threshold", type=float, default=None, help="override calibrated threshold")
    sp.add_argument("--out", default="reports/metrics.json", help="write metrics JSON here")
    sp.set_defaults(func=cmd_evaluate)
    return p


def main(argv: Optional[list] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s",
                        datefmt="%H:%M:%S")
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
