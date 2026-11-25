"""Render the setup-and-run tutorial video (docs/video/ev_can_ids_tutorial.mp4).

The terminal scenes replay real output captured from a fresh clone
(tutorial_captures.json); the code scenes show the real source files; the
dashboard chapter records the live dashboard. Narration, recording and
assembly reuse make_video.py.

Usage (from the repo root):
  pip install playwright kokoro-onnx soundfile imageio-ffmpeg
  python docs/video/make_tutorial.py --kokoro-dir /path/with/kokoro-v1.0.int8.onnx+voices-v1.0.bin
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_video as mv  # noqa: E402
from make_video import Line as L, Segment, Q, act, wait, ring, click, scroll_to, scroll_top, set_duration  # noqa: E402

HERE = mv.HERE
ROOT = mv.ROOT
CAPS = json.loads((HERE / "tutorial_captures.json").read_text())
BRANCH = "claude/dashboard-live-alerts-8mwbj9"


# ---------------------------------------------------------------------------
# helpers for the tutorial page
# ---------------------------------------------------------------------------

def js(expr: str, *args):
    async def run(page):
        await page.evaluate(expr, list(args) if len(args) != 1 else args[0])
    return run


def chapter(i):
    return js("(i) => chapter(i)", i)


def term(kicker, title, keep=False):
    return js("([k, t, keep]) => term(k, t, keep)", kicker, title, keep)


def typ(cmd):
    return js("(c) => type(c)", cmd)


def out(lines, gap=60, prompt=True):
    return js("([l, g, p]) => out(l, g, p)", lines, gap, prompt)


def note(kind, head, html):
    return js("([k, h, x]) => note(k, h, x)", kind, head, html)


def prompt(dirname):
    return js("(d) => setPrompt(d)", dirname)


def code_scene(kicker, title, path, spans):
    """spans: list of (first, last) 1-based inclusive line ranges from the real file."""
    src = (ROOT / path).read_text().splitlines()
    rows = []
    for i, (a, b) in enumerate(spans):
        if i:
            rows.append([None, ""])
        rows += [[n, src[n - 1]] for n in range(a, b + 1)]
    return js("([k, t, f, r]) => code(k, t, f, r)", kicker, title, path, rows)


def hl(a, b):
    return js("([a, b]) => hl(a, b)", a, b)


def code_note(head, html):
    return js("([h, x]) => codeNote(h, x)", head, html)


def find_line(path, needle, start=1):
    for n, line in enumerate((ROOT / path).read_text().splitlines(), 1):
        if n >= start and needle in line:
            return n
    raise ValueError(f"{needle!r} not found in {path}")


def strip_ts(lines, width=104):
    out_ = []
    for l in lines:
        if len(l) > 9 and l[2] == ":" and l[5] == ":" and l[8] == " ":
            l = l[9:]
        out_.append(l if len(l) <= width else l[: width - 1] + "…")
    return out_


async def move_threshold(page):
    await page.evaluate("""async () => {
      const s = document.getElementById('thr');
      const from = +s.value, to = 0.60;
      for (let i = 1; i <= 20; i++) {
        s.value = from + (to - from) * i / 20; s.dispatchEvent(new Event('input'));
        await new Promise(r => setTimeout(r, 70));
      }
    }""")


# ---------------------------------------------------------------------------
# Script
# ---------------------------------------------------------------------------

def build_script():
    F = "can_ids/features.py"
    M = "can_ids/model.py"
    E = "can_ids/engine.py"
    A = "can_ids/alerts.py"
    f_timing = find_line(F, "# --- timing")
    f_burst = find_line(F, "burstiness = float(len(tss))")
    m_train = find_line(M, "def train_model")
    m_fit = find_line(M, "forest.fit(X)")
    m_rules = find_line(M, "def rules(")
    m_base = find_line(M, "base = self.baselines.get(frame.can_id)", m_rules)
    m_ret = find_line(M, "return out", m_rules)
    e_proc = find_line(E, "def process(")
    e_extract = find_line(E, "X = self.fx.extract_many")
    e_obs = find_line(E, "self.alerts.observe(", e_proc)
    a_obs = find_line(A, "def observe(")
    a_need = find_line(A, "need = max(", a_obs)
    a_emit = find_line(A, 'self._emit("opened"', a_obs)
    a_key = find_line(A, "key = self.group_key", a_obs)
    a_app = find_line(A, "g.hits.append", a_obs)
    a_inc = find_line(A, "inc = Incident(", a_obs)
    a_set = find_line(A, "g.incident = inc", a_obs)
    e_rules = find_line(E, "reasons = self.model.rules", e_proc)
    e_flag = find_line(E, "frame.flagged = ml_hit", e_proc)
    e_cat = find_line(E, "cat = self.model.classify", e_proc)

    install_out = CAPS["install"]
    eval_out = CAPS["evaluate"]
    return [
        # ------------------------------------------------------------ intro
        Segment("scene", lead=0.8, lines=[
            L("In this tutorial, we'll set up the E-V CAN I-D-S project from scratch, run its tests, train the model, "
              "and launch the live dashboard.",
              "In this tutorial, we'll set up the EV CAN IDS project from scratch, run its tests, train the model "
              "and launch the live dashboard."),
            L("Every command and every output you'll see was captured from a fresh clone of the repository.",
              "Every command and every output you'll see was captured from a fresh clone of the repository.",
              hold=0.4),
        ]),
        # ------------------------------------------------------------ 1 prereqs
        Segment("scene", lead=0.2, lines=[
            L("You need three things: Python three point ten or newer, Git, and a web browser.",
              "You need three things: Python 3.10 or newer, Git, and a web browser.",
              action=act(chapter(0), js("""() => list('Step 1 · Prerequisites', 'What you need', [
                  ['🐍', 'Python 3.10 or newer', 'Check with <code>python3 --version</code>. Tested on Python 3.11.'],
                  ['🔧', 'Git', 'To clone the repository from GitHub.'],
                  ['🌐', 'A web browser', 'For the live dashboard at <code>localhost:8050</code>.'],
                  ['💾', 'No dataset download', 'A built-in EV network simulator means everything runs offline.']])"""),
                  wait(0.6), js("() => reveal(0)"), wait(1.2), js("() => reveal(1)"), wait(0.9), js("() => reveal(2)"))),
            L("No dataset download is needed. The project includes a simulator of an electric vehicle's network, "
              "so everything runs offline.",
              "No dataset download is needed. A built-in simulator of an EV network means everything runs offline.",
              action=js("() => reveal(3)"), hold=0.3),
        ]),
        # ------------------------------------------------------------ 2 get code
        Segment("scene", lead=0.2, lines=[
            L("First, clone the repository from GitHub, and move into the project folder.",
              "First, clone the repository from GitHub and move into the project folder.",
              action=act(chapter(1), prompt("~"), term("Step 2 · Get the code", "Clone the repository"),
                         typ("git clone https://github.com/SuhailKider/EV-CAN-IDS.git"),
                         out(CAPS["clone"], 300), typ("cd EV-CAN-IDS"), prompt("EV-CAN-IDS"), out([], 0))),
            L("The new code currently lives on a feature branch, so check it out. Once it's merged into main, "
              "you can skip this step.",
              "The new code currently lives on a feature branch, so check it out. "
              "Once it's merged into main, you can skip this step.",
              action=act(typ(f"git checkout {BRANCH}"), out(CAPS["checkout"], 250),
                         note("warn", "Until merged", f"Skip <code>git checkout</code> once <code>{BRANCH}</code> "
                                                      "is merged into <code>main</code>.")), hold=0.6),
        ]),
        # ------------------------------------------------------------ 3 install
        Segment("scene", lead=0.2, lines=[
            L("Create a virtual environment, so the project's packages stay separate from the rest of your system. "
              "Then activate it.",
              "Create a virtual environment so the project's packages stay separate from your system, then activate it.",
              action=act(chapter(2), term("Step 3 · Install", "Virtual environment + dependencies"),
                         typ("python3 -m venv .venv"), out([], 0), typ("source .venv/bin/activate"),
                         prompt("(.venv) EV-CAN-IDS"), out([], 0),
                         note("", "On Windows", "Activate with <code>.venv\\Scripts\\activate</code>"))),
            L("Now install the dependencies. The dev requirements file adds pytest on top of numpy, scikit-learn, "
              "joblib and flask. It took about four seconds here.",
              "Install the dependencies. requirements-dev.txt adds pytest to numpy, scikit-learn, joblib and Flask. "
              "It took about 4 seconds here.",
              action=act(typ("pip install -r requirements-dev.txt"), out(strip_ts(install_out, 100), 140),
                         note("good", "Installed", "numpy · scikit-learn · joblib · flask · pytest")), hold=0.4),
        ]),
        # ------------------------------------------------------------ 4 test
        Segment("scene", lead=0.2, lines=[
            L("Before running anything, check that the installation works. Run the test suite with pytest.",
              "Before running anything, check that the installation works: run the test suite with pytest.",
              action=act(chapter(3), term("Step 4 · Test", "Run the test suite"),
                         typ("pytest -q"), wait(0.8), out(CAPS["pytest"], 500))),
            L("All twenty tests pass. They cover the log parser, the features, detection of each attack type, "
              "the alert lifecycle, and the dashboard's API.",
              "All 20 tests pass. They cover the log parser, the features, detection of each attack type, "
              "the alert lifecycle and the dashboard API.",
              action=note("good", "20 passed", "parser · features · simulator · detection · alerts · engine · API"),
              hold=0.3),
        ]),
        # ------------------------------------------------------------ 5 train
        Segment("scene", lead=0.2, lines=[
            L("Now train the model. With no arguments, it trains on sixty seconds of simulated normal traffic: "
              "about twenty-eight thousand frames.",
              "Now train the model. By default it trains on 60 seconds of simulated normal traffic: about 28,000 frames.",
              action=act(chapter(4), term("Step 5 · Train", "Train the detector"),
                         typ("python -m can_ids train"), wait(0.4), out(strip_ts(CAPS["train"][:2]), 1600, False),
                         out(CAPS["train"][2:], 45))),
            L("It sets the alert threshold so that only half a percent of normal frames get flagged, "
              "and saves the model to the models folder.",
              "It sets the alert threshold so only 0.5% of normal frames get flagged, and saves the model to models/.",
              action=note("", "Calibrated", "Threshold <code>0.655</code> = 99.5th percentile of normal scores. "
                                            "Saved to <code>models/ids_model.joblib</code>.")),
            L("To train on the real H-C-R-L dataset instead, pass the attack-free log with the train-file option.",
              "To train on the real HCRL dataset instead, pass the attack-free log with --train-file.",
              action=note("", "Real data", "<code>python -m can_ids train --train-file data/Attack_free_dataset.txt</code>"),
              hold=0.4),
        ]),
        # ------------------------------------------------------------ 6 evaluate
        Segment("scene", lead=0.2, lines=[
            L("Next, measure how well it works. The evaluate command injects all three attacks into fresh simulated "
              "traffic, and scores every frame.",
              "Next, measure it. evaluate injects all three attacks into fresh simulated traffic and scores every frame.",
              action=act(chapter(5), term("Step 6 · Evaluate", "Measure detection quality"),
                         typ("python -m can_ids evaluate"), wait(0.5), out(strip_ts(eval_out), 90))),
            L("On its own, the Isolation Forest finds only sixteen percent of attack frames. With the learned rules, "
              "the hybrid detector finds ninety-nine point nine eight percent.",
              "On its own, the Isolation Forest finds only 16% of attack frames. "
              "With the learned rules, the hybrid detector finds 99.98%.",
              action=note("good", "Hybrid wins", "Recall 15.6% → <b>99.98%</b><br>F1 26% → <b>96%</b>"), hold=0.4),
        ]),
        # ------------------------------------------------------------ 7 code tour
        Segment("scene", lead=0.2, lines=[
            L("Here's how the code is organised. Each module in the can_ids package has one job.",
              "Here's how the code is organised. Each module in the can_ids package has one job.",
              action=act(chapter(6), js("() => showScene('arch')"), wait(0.4),
                         *[act(js("(m) => mod([m])", m), wait(0.55)) for m in
                           ("frame", "simulator", "features", "model", "engine", "alerts", "dashboard", "cli")])),
            L("A frame flows from the simulator, through the features and the model, into the engine, "
              "and out to the alerts and the dashboard.",
              "A frame flows from the simulator through features and the model into the engine, "
              "and out to alerts and the dashboard.",
              action=js("() => { const f = document.getElementById('flow'); f.style.color = '#e6edf5'; "
                        "f.style.fontSize = '22px'; }")),
            L("In features dot py, each frame updates a small history for its CAN I-D. "
              "For example, the time since that I-D was last seen.",
              "In features.py, each frame updates a small history for its CAN ID, e.g. the time since that ID was "
              "last seen…",
              action=act(code_scene("Step 7 · Code tour", "Streaming features", F,
                                    [(find_line(F, "def extract("), find_line(F, "def extract(")), (f_timing, f_burst)]),
                         wait(0.6), hl(f_timing + 1, f_timing + 6),
                         code_note("Per-ID state", "Each CAN ID keeps the last 20 deltas, timestamps and payloads."))),
            L("And how many frames arrived in the last ten milliseconds, which is what exposes a flood.",
              "…and how many frames arrived in the last 10 ms, which is what exposes a flood.",
              action=hl(f_burst - 5, f_burst)),
            L("In model dot py, train model fits an Isolation Forest on normal traffic only, then puts the threshold "
              "at the ninety-nine point five percentile of the training scores.",
              "In model.py, train_model fits an Isolation Forest on normal traffic only, then sets the threshold at "
              "the 99.5th percentile of training scores.",
              action=act(code_scene("Step 7 · Code tour", "Training & calibration", M, [(m_train, m_fit + 2)]),
                         wait(0.6), hl(m_fit - 3, m_fit), wait(2.6), hl(m_fit + 1, m_fit + 2),
                         code_note("No attack data", "Only normal frames are used, so unseen attacks can still be caught."))),
            L("The learned rules catch what the forest can't: an unknown I-D, an I-D sending faster than its normal "
              "period, or a payload that jumps outside its learned range.",
              "The learned rules catch what the forest can't: an unknown ID, an ID sending faster than its normal "
              "period, or a payload jump outside its learned range.",
              action=act(code_scene("Step 7 · Code tour", "Learned rules", M, [(m_rules, m_rules), (m_base, m_ret)]),
                         wait(0.4), hl(m_base, m_base + 2), wait(2.2), hl(m_base + 6, m_base + 9), wait(2.6),
                         hl(m_base + 10, m_ret))),
            L("The engine ties it together. It extracts features for each batch of frames, scores them, applies the "
              "rules, and sends every flagged frame to the alert manager.",
              "The engine ties it together: extract features for a batch, score, apply the rules, and send flagged "
              "frames to the alert manager.",
              action=act(code_scene("Step 7 · Code tour", "The real-time loop", E,
                                    [(e_proc, e_proc), (e_extract, e_extract + 1), (e_rules - 2, e_flag),
                                     (e_cat - 1, e_obs + 1)]),
                         wait(0.4), hl(e_extract, e_extract + 1), wait(2.4), hl(e_rules, e_flag),
                         wait(2.4), hl(e_cat - 1, e_obs + 1))),
            L("The alert manager groups flagged frames by attack type. Only when enough arrive within one second "
              "does it open an incident. That's how thousands of frames become one alert.",
              "The alert manager groups flagged frames by attack type and opens an incident only when enough arrive "
              "within 1 s: thousands of frames become one alert.",
              action=act(code_scene("Step 7 · Code tour", "From frames to incidents", A,
                                    [(a_obs, a_obs), (a_key, a_app), (a_need, a_need + 2), (a_inc, a_inc + 1),
                                     (a_set, a_emit)]),
                         wait(0.4), hl(a_key, a_app), wait(2.6), hl(a_need, a_need + 2), wait(2.6),
                         hl(a_inc, a_emit)), hold=0.4),
        ]),
        # ------------------------------------------------------------ 8 dashboard
        Segment("scene", lead=0.2, lines=[
            L("Time for the fun part. Start the live dashboard. The open flag opens it in your browser.",
              "Time for the fun part: start the live dashboard. --open opens it in your browser.",
              action=act(chapter(7), term("Step 8 · Dashboard", "Launch the live dashboard"),
                         typ("python -m can_ids dashboard --open"), wait(0.5), out(strip_ts(CAPS["dashboard"]), 220, False),
                         note("", "Open", "<code>http://localhost:8050</code><br>Stop with <code>Ctrl+C</code>")),
              hold=0.3),
        ]),
        Segment("demo", lead=0.8, tail=1.0, lines=[
            L("It opens on a healthy bus: about five hundred frames per second, and the status reads: bus secure.",
              "It opens on a healthy bus: about 500 frames per second, and the status reads BUS SECURE.",
              action=act(wait(0.3), lambda p: ring(p, f"{Q}('.kpis')", 3.2), lambda p: ring(p, f"{Q}('#status')", 2.0))),
            L("Use the attack simulator on the right. Choose a duration, then launch a denial-of-service flood.",
              "Use the attack simulator on the right: choose a duration, then launch a DoS flood.",
              action=act(lambda p: ring(p, f"{Q}('#card-attack')", 2.2), lambda p: set_duration(p, 12),
                         lambda p: ring(p, f"{Q}('.attack-opts')", 1.4),
                         lambda p: click(p, ".attack-btn[data-kind=dos]"))),
            L("Within a second the status turns red, and a critical incident appears in the alert feed, "
              "with its evidence and a recommended response.",
              "Within a second the status turns red and a CRITICAL incident appears, with its evidence and a "
              "recommended response.",
              action=act(lambda p: ring(p, f"{Q}('#status')", 2.0), lambda p: scroll_to(p, f"{Q}('#card-alerts')"),
                         lambda p: ring(p, f"{Q}('.alert')", 4.5))),
            L("Click acknowledge once you've seen it. The CSV and Report buttons export incidents for your records.",
              "Click Acknowledge once you've seen it. CSV and Report export incidents for your records.",
              action=act(lambda p: click(p, ".alert [data-ack]"), wait(0.8),
                         lambda p: ring(p, f"{Q}('#card-alerts .head-actions')", 3.0, pad=6))),
            L("Now try impersonation. Pick the target E-C-U, here the motor inverter, and launch.",
              "Now try impersonation: pick the target ECU (here the motor inverter) and launch.",
              action=act(scroll_top, lambda p: ring(p, f"{Q}('#target')", 1.6, pad=6),
                         lambda p: set_duration(p, 20), lambda p: click(p, ".attack-btn[data-kind=impersonation]"))),
            L("The detection quality panel measures accuracy live, because the simulator knows which frames are "
              "malicious. Drag the threshold slider to trade missed attacks against false alarms.",
              "The quality panel measures accuracy live, because the simulator knows which frames are malicious. "
              "Drag the threshold to trade missed attacks against false alarms.",
              action=act(wait(0.5), lambda p: scroll_to(p, f"{Q}('#card-quality')"),
                         lambda p: ring(p, f"{Q}('#card-quality')", 3.4),
                         lambda p: ring(p, f"{Q}('.threshold')", 0.1, pad=6), move_threshold, wait(1.2),
                         lambda p: click(p, "#btn-thr-reset"))),
            L("Switch to M-L only to see what the Isolation Forest misses without the rules, then switch back to hybrid.",
              "Switch to ML only to see what the Isolation Forest misses without the rules, then back to Hybrid.",
              action=act(lambda p: click(p, "#mode button[data-m=ml]"), wait(2.6),
                         lambda p: click(p, "#mode button[data-m=hybrid]")), hold=0.6),
        ]),
        # ------------------------------------------------------------ 9 more
        Segment("scene", lead=0.3, lines=[
            L("If you don't need the browser, the monitor command prints alerts straight to the terminal. "
              "The demo flag injects all three attacks for you.",
              "No browser needed? monitor prints alerts straight to the terminal; --demo injects all three attacks.",
              action=act(chapter(8), term("Step 9 · More ways to run", "Terminal-only monitor"),
                         typ("python -m can_ids monitor --demo --speed 3 --duration 50"), wait(0.4),
                         out(strip_ts(CAPS["monitor"][:5]), 700, False))),
            L("Each attack opens one incident, and resolves it when the traffic returns to normal.",
              "Each attack opens one incident and resolves it when traffic returns to normal.",
              action=out(strip_ts(CAPS["monitor"][5:]), 650)),
            L("To use the real H-C-R-L dataset, put its text files in a data folder, and pass them to train, evaluate "
              "or the dashboard. You can also forward alerts to Slack with a webhook, or run everything in Docker.",
              "To use the real HCRL dataset, put its .txt files in data/ and pass them in. You can also forward "
              "alerts to Slack with --webhook, or run it all in Docker.",
              action=act(note("", "Real HCRL data", "<code>--train-file data/Attack_free_dataset.txt --retrain</code><br>"
                                                    "<code>--replay data/DoS_attack_dataset.txt</code>"),
                         wait(2.2), note("", "Slack / Teams", "<code>--webhook https://hooks.slack.com/…</code>"),
                         wait(2.0), note("", "Docker", "<code>docker build -t ev-can-ids .</code><br>"
                                                      "<code>docker run -p 8050:8050 ev-can-ids</code>")), hold=0.4),
        ]),
        Segment("scene", lead=0.2, tail=2.2, lines=[
            L("Here's everything in one place. Clone, install, test, train, evaluate, and run. "
              "That's the whole project, up and running.",
              "Here's everything in one place: clone, install, test, train, evaluate and run. "
              "That's the whole project, up and running.",
              action=act(chapter(9), js("() => showScene('cheat')"))),
        ]),
    ]


# ---------------------------------------------------------------------------

async def record(script, voice, work: Path, dashboard_url: str):
    from playwright.async_api import async_playwright

    for seg in script:
        for line in seg.lines:
            voice.say(line.say)

    frames_dir = work / "frames"
    shutil.rmtree(frames_dir, ignore_errors=True)
    frames_dir.mkdir(parents=True)
    rec = mv.Recorder(frames_dir)
    timeline: list = []
    exe = next(Path("/opt/pw-browsers").glob("chromium-*/chrome-linux*/chrome"), None)
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(executable_path=str(exe) if exe else None)
        ctx = await browser.new_context(viewport={"width": mv.VIEW_W, "height": mv.VIEW_H},
                                        device_scale_factor=mv.SCALE)
        tut = await ctx.new_page()
        await tut.goto((HERE / "tutorial.html").as_uri())
        dash = await ctx.new_page()
        await dash.goto(dashboard_url)
        await dash.evaluate(mv.OVERLAY_JS)
        await asyncio.sleep(1.5)

        current = None
        for seg in script:
            page = dash if seg.kind == "demo" else tut
            if page is not current:
                if current is not None:
                    await rec.stop()
                await page.bring_to_front()
                await rec.start(page)
                current = page
            await mv.play_segment(page, seg, voice, rec, timeline)
            print(f"  recorded {seg.kind:<5} {timeline[-1][1] - timeline[-1][0]:5.1f}s", flush=True)
        await rec.stop()
        await browser.close()
    return rec.frames, timeline


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kokoro-dir", type=Path)
    ap.add_argument("--voice", default="af_heart")
    ap.add_argument("--work", type=Path, default=Path("build/tutorial"))
    ap.add_argument("--out", type=Path, default=HERE / "ev_can_ids_tutorial.mp4")
    args = ap.parse_args()

    try:
        import imageio_ffmpeg
        ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    except ImportError:
        ffmpeg = shutil.which("ffmpeg") or sys.exit("ffmpeg not found")

    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    voice = mv.Voice(args.kokoro_dir, args.voice, work / "tts")
    script = build_script()

    server = subprocess.Popen(
        [sys.executable, "-m", "can_ids", "dashboard", "--port", str(mv.PORT), "--model", str(work / "model.joblib"),
         "--alert-log", str(work / "alerts.jsonl")],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        url = f"http://127.0.0.1:{mv.PORT}/"
        for _ in range(120):
            try:
                urllib.request.urlopen(url, timeout=1).close()
                break
            except OSError:
                time.sleep(0.5)
        frames, timeline = asyncio.run(record(script, voice, work, url))
    finally:
        server.terminate()
    mv.assemble(frames, timeline, work, args.out.resolve(), ffmpeg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
