"""Render the project explainer video (docs/video/ev_can_ids_explainer.mp4).

Pipeline:
  1. Narration: one WAV per sentence via Kokoro TTS (offline), falling back
     to espeak-ng.
  2. Picture: Playwright drives docs/video/scenes.html (animated explainer
     scenes) and the real dashboard (live demo), timed to the narration.
     Frames are captured with the Chrome DevTools screencast.
  3. Assembly: ffmpeg turns the timestamped frames into 30 fps H.264 and
     muxes the narration track.

Usage (from the repo root):
  pip install playwright kokoro-onnx soundfile imageio-ffmpeg
  python docs/video/make_video.py --kokoro-dir /path/with/kokoro-v1.0.int8.onnx+voices-v1.0.bin
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import shutil
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, List, Optional

import numpy as np
import soundfile as sf

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SR = 24000
VIEW_W, VIEW_H, SCALE = 1600, 900, 1.2  # rendered at 1920x1080
GAP = 0.35                               # pause after each sentence
PORT = 8077

Action = Callable[["object"], Awaitable[None]]


@dataclass
class Line:
    say: str                    # text sent to TTS (acronyms spelled out)
    caption: str                # on-screen caption
    cue: Optional[str] = None   # scenes.html cue fired when the line starts
    action: Optional[Action] = None  # dashboard action started with the line
    hold: float = 0.0           # extra seconds after the line


@dataclass
class Segment:
    kind: str                   # "scene" | "demo"
    lines: List[Line]
    scene: str = ""
    lead: float = 0.7
    tail: float = 0.9
    audio: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Dashboard choreography
# ---------------------------------------------------------------------------

OVERLAY_JS = r"""
(() => {
  const st = document.createElement('style');
  st.textContent = `
    #vcap { position: fixed; left: 50%; bottom: 30px; transform: translateX(-50%); max-width: 1050px; text-align: center;
      background: rgba(5,8,13,.86); border: 1px solid rgba(138,155,176,.3); color: #f1f5f9;
      font: 500 22px/1.4 Inter, "DejaVu Sans", sans-serif; padding: 11px 22px; border-radius: 12px;
      opacity: 0; transition: opacity .25s; z-index: 1000; pointer-events: none; }
    #vcap.on { opacity: 1; }
    #vring { position: fixed; border: 3px solid #38bdf8; border-radius: 14px; z-index: 900; pointer-events: none;
      box-shadow: 0 0 0 9999px rgba(0,0,0,.38), 0 0 30px rgba(56,189,248,.6); opacity: 0; transition: all .45s ease; }
    #vring.on { opacity: 1; }
    #vcur { position: fixed; width: 26px; height: 26px; z-index: 1001; pointer-events: none; left: 800px; top: 520px;
      transition: left .9s cubic-bezier(.3,.7,.2,1), top .9s cubic-bezier(.3,.7,.2,1); }
    #vcur svg { width: 26px; height: 26px; filter: drop-shadow(0 2px 4px rgba(0,0,0,.6)); }
    #vcur::after { content: ""; position: absolute; left: -14px; top: -14px; width: 28px; height: 28px; border-radius: 50%;
      border: 3px solid #f59e0b; opacity: 0; }
    #vcur.click::after { animation: vclick .6s ease-out; }
    @keyframes vclick { from { opacity: 1; transform: scale(.4); } to { opacity: 0; transform: scale(1.8); } }
  `;
  document.head.appendChild(st);
  const cap = Object.assign(document.createElement('div'), { id: 'vcap' });
  const ring = Object.assign(document.createElement('div'), { id: 'vring' });
  const cur = Object.assign(document.createElement('div'), { id: 'vcur' });
  cur.innerHTML = '<svg viewBox="0 0 24 24"><path d="M4 2l16 9-7 2-3 7z" fill="#fff" stroke="#0b1017" stroke-width="1.5"/></svg>';
  document.body.append(cap, ring, cur);
  window.caption = (t) => { cap.textContent = t || ''; cap.classList.toggle('on', !!t); };
  window.ringOn = (r, pad = 8) => {
    Object.assign(ring.style, { left: (r.x - pad) + 'px', top: (r.y - pad) + 'px',
      width: (r.width + 2 * pad) + 'px', height: (r.height + 2 * pad) + 'px' });
    ring.classList.add('on');
  };
  window.ringOff = () => ring.classList.remove('on');
  window.cursorTo = (x, y) => { cur.style.left = x + 'px'; cur.style.top = y + 'px'; };
  window.cursorClick = () => { cur.classList.remove('click'); void cur.offsetWidth; cur.classList.add('click'); };
})();
"""


async def rect(page, js_expr: str):
    return await page.evaluate(f"(() => {{ const el = {js_expr}; if (!el) return null;"
                               " const r = el.getBoundingClientRect();"
                               " return {x: r.x, y: r.y, width: r.width, height: r.height}; })()")


async def scroll_to(page, js_expr: str, offset: int = 90) -> None:
    await page.evaluate(f"(() => {{ const el = {js_expr}; if (!el) return;"
                        f" window.scrollTo({{top: el.getBoundingClientRect().top + window.scrollY - {offset},"
                        " behavior: 'smooth'}); })()")
    await asyncio.sleep(0.9)


async def scroll_top(page) -> None:
    await page.evaluate("window.scrollTo({top: 0, behavior: 'smooth'})")
    await asyncio.sleep(0.9)


async def ring(page, js_expr: str, seconds: float, pad: int = 8) -> None:
    r = await rect(page, js_expr)
    if r:
        await page.evaluate("([r, p]) => ringOn(r, p)", [r, pad])
        await asyncio.sleep(seconds)
        await page.evaluate("ringOff()")


async def click(page, selector: str) -> None:
    r = await rect(page, f"document.querySelector({selector!r})")
    if not r:
        return
    x, y = r["x"] + r["width"] * 0.82, r["y"] + r["height"] * 0.5
    await page.evaluate("([x, y]) => cursorTo(x, y)", [x, y])
    await asyncio.sleep(1.0)
    await page.evaluate("cursorClick()")
    await page.click(selector)


async def set_duration(page, seconds: int) -> None:
    await page.evaluate(f"(() => {{ const d = document.getElementById('duration'); d.value = {seconds};"
                        " d.dispatchEvent(new Event('input')); })()")


Q = "document.querySelector"


def act(*steps):
    """Run steps sequentially as one background action."""
    async def run(page):
        for s in steps:
            await s(page)
    return run


def wait(s):
    async def f(page):
        await asyncio.sleep(s)
    return f


# ---------------------------------------------------------------------------
# Script
# ---------------------------------------------------------------------------

def build_script() -> List[Segment]:
    L = Line
    return [
        Segment("scene", scene="title", lead=0.8, tail=1.0, lines=[
            L("This is E-V CAN I-D-S: a real-time intrusion detection system for electric vehicles, powered by machine learning.",
              "This is EV CAN IDS: a real-time intrusion detection system for electric vehicles, powered by machine learning.",
              cue="tags"),
        ]),
        Segment("scene", scene="bus", lines=[
            L("Inside every electric vehicle, dozens of control units talk over one shared network: the CAN bus. "
              "The battery, the motor inverter, the brakes.",
              "Inside every electric vehicle, dozens of control units talk over one shared network: the CAN bus. "
              "The battery, the motor inverter, the brakes.", cue="ecus"),
            L("CAN was designed in the nineteen eighties. It has no authentication and no encryption, "
              "and every message is broadcast to everyone.",
              "CAN was designed in the 1980s. It has no authentication and no encryption, "
              "and every message is broadcast to everyone.", cue="flaws"),
            L("So any device that reaches the bus, through the diagnostic port or a hacked unit, "
              "can send any message it likes.",
              "So any device that reaches the bus, through the diagnostic port or a hacked unit, "
              "can send any message it likes.", cue="attacker", hold=0.6),
        ]),
        Segment("scene", scene="attacks", lines=[
            L("That makes three classic attacks possible.", "That makes three classic attacks possible.", cue="head"),
            L("A denial-of-service flood, which drowns out legitimate traffic.",
              "A denial-of-service flood, which drowns out legitimate traffic.", cue="dos"),
            L("Fuzzing, which sprays random identifiers and random data.",
              "Fuzzing, which sprays random identifiers and random data.", cue="fuzzy"),
            L("And impersonation, where the attacker forges commands using a real unit's identity, "
              "like the motor inverter.",
              "And impersonation, where the attacker forges commands using a real unit's identity, "
              "like the motor inverter.", cue="imp"),
        ]),
        Segment("scene", scene="pipeline", lines=[
            L("The I-D-S watches every single frame on the bus.",
              "The IDS watches every single frame on the bus.", cue="frames"),
            L("For each one, it computes twelve behavioural features: timing, burstiness, payload entropy, "
              "bit flips, and how predictable the data is.",
              "For each one, it computes twelve behavioural features: timing, burstiness, payload entropy, "
              "bit flips, and how predictable the data is.", cue="features"),
            L("An Isolation Forest, trained only on normal traffic, scores how unusual each frame looks.",
              "An Isolation Forest, trained only on normal traffic, scores how unusual each frame looks.",
              cue="iforest"),
            L("Lightweight rules, learned from the same normal data, check for unknown identifiers, "
              "wrong timing, and impossible payload jumps.",
              "Lightweight rules, learned from the same normal data, check for unknown identifiers, "
              "wrong timing and impossible payload jumps.", cue="rules"),
            L("Flagged frames are grouped into incidents, classified, explained, and sent to the dashboard, "
              "a log file, and team chat.",
              "Flagged frames are grouped into incidents, classified, explained, and sent to the dashboard, "
              "a log file and team chat.", cue="incident", hold=0.5),
        ]),
        Segment("demo", lead=1.0, tail=1.2, lines=[
            L("Here is the live dashboard, monitoring a simulated E-V bus at around five hundred frames per second.",
              "Here is the live dashboard, monitoring a simulated EV bus at around 500 frames per second.",
              action=act(wait(0.4), lambda p: ring(p, f"{Q}('.kpis')", 4.2))),
            L("Everything is normal, so the status reads: bus secure.",
              "Everything is normal, so the status reads: bus secure.",
              action=lambda p: ring(p, f"{Q}('#status')", 2.6)),
            L("Let's launch a denial-of-service flood.",
              "Let's launch a denial-of-service flood.",
              action=act(lambda p: set_duration(p, 14), lambda p: click(p, ".attack-btn[data-kind=dos]"))),
            L("Within a second, the status turns red, and thousands of malicious frames become one critical incident.",
              "Within a second, the status turns red, and thousands of malicious frames become one critical incident.",
              action=act(lambda p: ring(p, f"{Q}('#status')", 2.4),
                         lambda p: scroll_to(p, f"{Q}('#card-alerts')"),
                         lambda p: ring(p, f"{Q}('.alert')", 3.0))),
            L("It even explains why: identifier zero is unknown, and it is sending a thousand messages a second.",
              "It explains why: ID 0x000 is unknown, and it is sending 1,000 messages a second.",
              action=lambda p: ring(p, f"{Q}('.alert .a-why')", 6.0, pad=10)),
            L("Now the hardest attack: impersonating the motor inverter.",
              "Now the hardest attack: impersonating the motor inverter.",
              action=act(scroll_top, lambda p: set_duration(p, 22),
                         lambda p: click(p, ".attack-btn[data-kind=impersonation]"))),
            L("The attacker uses a legitimate identifier, so a simple whitelist can't catch it. "
              "But the I-D-S notices the inverter now sends every five milliseconds instead of ten, "
              "with impossible jumps in its data.",
              "The attacker uses a legitimate ID, so a simple whitelist can't catch it. "
              "But the IDS notices the inverter now sends every ~5 ms instead of 10, with impossible jumps in its data.",
              action=act(wait(1.2), lambda p: scroll_to(p, f"{Q}('#card-alerts')"),
                         lambda p: ring(p, f"{Q}('.alert')", 9.0))),
            L("In the CAN I-D monitor, the inverter shows double its normal rate.",
              "In the CAN ID monitor, the inverter shows double its normal rate.",
              action=act(lambda p: scroll_to(p, f"{Q}('#card-ids')"),
                         lambda p: ring(p, "[...document.querySelectorAll('#ids-body tr')]"
                                           ".find(r => r.textContent.includes('0x0B4'))", 3.5, pad=4))),
            L("Fuzzing lights up hundreds of unknown identifiers, and every flagged frame is labelled in the live log.",
              "Fuzzing lights up hundreds of unknown IDs, and every flagged frame is labelled in the live log.",
              action=act(scroll_top, lambda p: set_duration(p, 12),
                         lambda p: click(p, ".attack-btn[data-kind=fuzzy]"), wait(1.5),
                         lambda p: scroll_to(p, f"{Q}('#card-frames')"),
                         lambda p: ring(p, f"{Q}('#card-frames')", 3.0))),
            L("And because the simulator knows which frames are malicious, the dashboard measures itself live: "
              "every attack type detected.",
              "Because the simulator knows which frames are malicious, the dashboard measures itself live: "
              "every attack type detected.",
              action=act(lambda p: scroll_to(p, f"{Q}('#card-quality')"),
                         lambda p: ring(p, f"{Q}('#card-quality')", 6.5)), hold=0.8),
        ]),
        Segment("scene", scene="results", lines=[
            L("Why combine machine learning with rules? On its own, the Isolation Forest caught only sixteen percent "
              "of attack frames, and missed every single denial-of-service frame.",
              "Why combine ML with rules? On its own, the Isolation Forest caught only 16% of attack frames, "
              "and missed every single DoS frame.", cue="if"),
            L("It can't learn from things that never change in normal traffic, like whether an identifier is known.",
              "It can't learn from things that never change in normal traffic, like whether an ID is known.",
              cue="why"),
            L("The hybrid detector catches ninety-nine point nine eight percent of attack frames, and lifts the F1 score "
              "from twenty-six to ninety-six percent, with about half a percent false alarms on clean traffic.",
              "The hybrid detector catches 99.98% of attack frames and lifts F1 from 26% to 96%, "
              "with ~0.5% false alarms on clean traffic.", cue="hy", hold=0.6),
        ]),
        Segment("scene", scene="outro", tail=2.2, lines=[
            L("Everything runs offline, in Python, with a single command.",
              "Everything runs offline, in Python, with a single command.", cue="cmd"),
            L("E-V CAN I-D-S. Unsupervised, explainable, real-time protection for the vehicle network.",
              "EV CAN IDS. Unsupervised, explainable, real-time protection for the vehicle network.", cue="tag"),
        ]),
    ]


# ---------------------------------------------------------------------------
# TTS
# ---------------------------------------------------------------------------

class Voice:
    def __init__(self, kokoro_dir: Optional[Path], voice: str, cache: Path) -> None:
        self.cache = cache
        cache.mkdir(parents=True, exist_ok=True)
        self.voice = voice
        self.kokoro = None
        if kokoro_dir:
            from kokoro_onnx import Kokoro
            self.kokoro = Kokoro(str(kokoro_dir / "kokoro-v1.0.int8.onnx"), str(kokoro_dir / "voices-v1.0.bin"))
        elif not shutil.which("espeak-ng"):
            sys.exit("Need --kokoro-dir or espeak-ng for narration")

    def say(self, text: str) -> np.ndarray:
        key = hashlib.sha1(f"{self.voice}|{bool(self.kokoro)}|{text}".encode()).hexdigest()[:16]
        path = self.cache / f"{key}.wav"
        if not path.exists():
            if self.kokoro:
                samples, sr = self.kokoro.create(text, voice=self.voice, speed=1.0, lang="en-us")
                sf.write(path, samples, sr)
            else:
                subprocess.run(["espeak-ng", "-v", "en-us", "-s", "160", "-w", str(path), text], check=True)
        data, sr = sf.read(path, dtype="float32")
        if data.ndim > 1:
            data = data.mean(axis=1)
        if sr != SR:  # simple linear resample (espeak is 22.05 kHz)
            x = np.linspace(0, len(data), int(len(data) * SR / sr), endpoint=False)
            data = np.interp(x, np.arange(len(data)), data).astype("float32")
        return data


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------

class Recorder:
    def __init__(self, frames_dir: Path) -> None:
        self.dir = frames_dir
        self.frames: List[tuple] = []  # (timestamp, path)
        self.cdp = None
        self._n = 0

    async def start(self, page) -> None:
        self.cdp = await page.context.new_cdp_session(page)

        async def on_frame(p):
            self._n += 1
            path = self.dir / f"f{self._n:06d}.jpg"
            path.write_bytes(base64.b64decode(p["data"]))
            self.frames.append((p["metadata"]["timestamp"], path))
            try:
                await self.cdp.send("Page.screencastFrameAck", {"sessionId": p["sessionId"]})
            except Exception:
                pass

        self.cdp.on("Page.screencastFrame", lambda p: asyncio.ensure_future(on_frame(p)))
        await self.cdp.send("Page.startScreencast", {"format": "jpeg", "quality": 92,
                                                     "maxWidth": 1920, "maxHeight": 1080, "everyNthFrame": 1})

    async def stop(self) -> None:
        await self.cdp.send("Page.stopScreencast")
        await asyncio.sleep(0.3)


async def play_segment(page, seg: Segment, voice: Voice, rec: Recorder, timeline: list) -> None:
    """Play one segment; append (start, end) wall-clock span and audio events."""
    t_start = time.time()
    await asyncio.sleep(seg.lead)
    tasks = []
    for line in seg.lines:
        audio = voice.say(line.say)
        t = time.time()
        seg.audio.append((t, audio))
        await page.evaluate("(t) => window.caption(t)", line.caption)
        if line.cue:
            await page.evaluate("(c) => window.cue(c)", line.cue)
        if line.action:
            tasks.append(asyncio.ensure_future(line.action(page)))
        await asyncio.sleep(len(audio) / SR + GAP + line.hold)
    await page.evaluate("window.caption('')")
    await asyncio.sleep(seg.tail)
    for task in tasks:
        if not task.done():
            await task
    timeline.append((t_start, time.time(), seg))


async def record(script: List[Segment], voice: Voice, work: Path, dashboard_url: str) -> tuple:
    from playwright.async_api import async_playwright

    # Pre-synthesise narration so recording timing is not affected by TTS speed.
    for seg in script:
        for line in seg.lines:
            voice.say(line.say)

    frames_dir = work / "frames"
    shutil.rmtree(frames_dir, ignore_errors=True)
    frames_dir.mkdir(parents=True)
    rec = Recorder(frames_dir)
    timeline: list = []
    exe = next(Path("/opt/pw-browsers").glob("chromium-*/chrome-linux/chrome"), None)
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(executable_path=str(exe) if exe else None)
        ctx = await browser.new_context(viewport={"width": VIEW_W, "height": VIEW_H}, device_scale_factor=SCALE)
        scenes = await ctx.new_page()
        await scenes.goto((HERE / "scenes.html").as_uri())
        dash = await ctx.new_page()
        await dash.goto(dashboard_url)
        await dash.evaluate(OVERLAY_JS)
        await asyncio.sleep(2)

        current = None
        for seg in script:
            page = dash if seg.kind == "demo" else scenes
            if page is not current:
                if current is not None:
                    await rec.stop()
                await page.bring_to_front()
                await rec.start(page)
                current = page
            if seg.kind == "scene":
                await page.evaluate("(s) => window.showScene(s)", seg.scene)
            await play_segment(page, seg, voice, rec, timeline)
            print(f"  recorded {seg.kind:<5} {seg.scene or 'dashboard':<10} "
                  f"{timeline[-1][1] - timeline[-1][0]:5.1f}s", flush=True)
        await rec.stop()
        await browser.close()
    return rec.frames, timeline


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

def assemble(frames: list, timeline: list, work: Path, out: Path, ffmpeg: str) -> None:
    t0, t_end = timeline[0][0], timeline[-1][1]
    total = t_end - t0
    # Keep only frames inside the recorded spans; the frame shown at a
    # segment's start is the last frame captured before it.
    frames = sorted(frames)
    lines = []
    usable = [(t, p) for t, p in frames if t0 - 2 <= t <= t_end]
    for i, (t, p) in enumerate(usable):
        nxt = usable[i + 1][0] if i + 1 < len(usable) else t_end
        start = max(t, t0)
        dur = nxt - start
        if dur <= 0:
            continue
        lines.append(f"file '{p}'\nduration {dur:.4f}")
    lines.append(f"file '{usable[-1][1]}'")
    concat = work / "frames.txt"
    concat.write_text("\n".join(lines) + "\n")

    audio = np.zeros(int(total * SR) + SR, dtype="float32")
    for _, _, seg in timeline:
        for t, clip in seg.audio:
            i = int((t - t0) * SR)
            audio[i:i + len(clip)] += clip[: len(audio) - i]
    peak = np.abs(audio).max() or 1.0
    audio = audio / peak * 0.89
    wav = work / "narration.wav"
    sf.write(wav, audio[: int(total * SR)], SR)

    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [ffmpeg, "-y", "-hide_banner", "-loglevel", "error",
           "-f", "concat", "-safe", "0", "-i", str(concat), "-i", str(wav),
           "-vf", "scale=1920:1080:flags=lanczos,fps=30,format=yuv420p",
           "-c:v", "libx264", "-preset", "slow", "-crf", "22", "-tune", "stillimage",
           "-c:a", "aac", "-b:a", "160k", "-movflags", "+faststart", "-shortest", str(out)]
    subprocess.run(cmd, check=True)
    print(f"Wrote {out} ({total:.1f}s, {out.stat().st_size / 1e6:.1f} MB)")


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kokoro-dir", type=Path, help="folder with kokoro-v1.0.int8.onnx and voices-v1.0.bin")
    ap.add_argument("--voice", default="af_heart")
    ap.add_argument("--work", type=Path, default=Path("build/video"))
    ap.add_argument("--out", type=Path, default=HERE / "ev_can_ids_explainer.mp4")
    args = ap.parse_args()

    try:
        import imageio_ffmpeg
        ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    except ImportError:
        ffmpeg = shutil.which("ffmpeg") or sys.exit("ffmpeg not found")

    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    voice = Voice(args.kokoro_dir, args.voice, work / "tts")
    script = build_script()

    model = work / "model.joblib"
    server = subprocess.Popen(
        [sys.executable, "-m", "can_ids", "dashboard", "--port", str(PORT), "--model", str(model),
         "--alert-log", str(work / "alerts.jsonl")],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        url = f"http://127.0.0.1:{PORT}/"
        for _ in range(120):  # first run trains the model (~4 s)
            try:
                urllib.request.urlopen(url, timeout=1).close()
                break
            except OSError:
                time.sleep(0.5)
        print("Dashboard up; letting traffic build for 20 s…", flush=True)
        time.sleep(20)
        frames, timeline = asyncio.run(record(script, voice, work, url))
    finally:
        server.terminate()
    assemble(frames, timeline, work, args.out.resolve(), ffmpeg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
