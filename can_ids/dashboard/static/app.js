/* EV CAN IDS live dashboard – no dependencies, works offline. */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const fmtInt = (n) => (n ?? 0).toLocaleString("en-US");
  const pct = (v, d = 1) => (v == null ? "–" : (v * 100).toFixed(d) + "%");
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  let state = null;
  let soundOn = true;
  let alertFilter = "all";
  const seenIncidents = new Set();
  let firstPayload = true;
  let targetsFilled = new Set();

  // ------------------------------------------------------------ preferences
  const store = {
    get(k, d) { try { const v = localStorage.getItem("canids:" + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem("canids:" + k, JSON.stringify(v)); } catch { /* ignore */ } },
  };
  document.documentElement.dataset.theme = store.get("theme", "dark");
  soundOn = store.get("sound", true);
  $("btn-sound").setAttribute("aria-pressed", String(soundOn));

  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

  // ------------------------------------------------------------ API helpers
  async function post(url, body) {
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
    if (!r.ok) console.warn(url, await r.text());
    return r;
  }

  // ------------------------------------------------------------ audio
  let audioCtx = null;
  function beep(severity) {
    if (!soundOn) return;
    try {
      audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
      const pattern = severity === "CRITICAL" ? [880, 660, 880] : severity === "HIGH" ? [760, 560] : [520];
      pattern.forEach((f, i) => {
        const o = audioCtx.createOscillator(), g = audioCtx.createGain();
        o.type = "square"; o.frequency.value = f;
        const t = audioCtx.currentTime + i * 0.16;
        g.gain.setValueAtTime(0.0001, t);
        g.gain.exponentialRampToValueAtTime(0.06, t + 0.01);
        g.gain.exponentialRampToValueAtTime(0.0001, t + 0.13);
        o.connect(g).connect(audioCtx.destination);
        o.start(t); o.stop(t + 0.14);
      });
    } catch { /* audio unavailable */ }
  }

  // ------------------------------------------------------------ canvas chart helpers
  function setupCanvas(cv) {
    const dpr = window.devicePixelRatio || 1;
    // The CSS height is fixed from the original height attribute; reading
    // clientHeight back would feed the backing-store size into the layout.
    if (!cv.dataset.h) cv.dataset.h = cv.getAttribute("height");
    const h = +cv.dataset.h;
    cv.style.height = h + "px";
    const w = cv.clientWidth;
    if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
      cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
    }
    const ctx = cv.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    return { ctx, w, h };
  }

  function niceMax(v) {
    if (v <= 0) return 1;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * p) return m * p;
    return 10 * p;
  }

  function axes(ctx, box, yMax, yTicks, fmtY, xLabels) {
    ctx.font = "11px " + css("--sans");
    ctx.fillStyle = css("--muted");
    ctx.strokeStyle = css("--grid");
    ctx.lineWidth = 1;
    ctx.textAlign = "right"; ctx.textBaseline = "middle";
    for (let i = 0; i <= yTicks; i++) {
      const v = (yMax * i) / yTicks;
      const y = box.y + box.h - (v / yMax) * box.h;
      ctx.beginPath(); ctx.moveTo(box.x, Math.round(y) + 0.5); ctx.lineTo(box.x + box.w, Math.round(y) + 0.5); ctx.stroke();
      ctx.fillText(fmtY(v), box.x - 6, y);
    }
    if (xLabels) {
      ctx.textAlign = "center"; ctx.textBaseline = "top";
      xLabels.forEach(([x, label]) => ctx.fillText(label, x, box.y + box.h + 5));
    }
  }

  function path(ctx, pts) {
    ctx.beginPath();
    pts.forEach(([x, y], i) => (i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
  }

  function drawTimeline() {
    if (!state) return;
    const tl = state.timeline;
    const N = 120;
    // --- traffic ---
    {
      const { ctx, w, h } = setupCanvas($("chart-traffic"));
      const box = { x: 46, y: 8, w: w - 56, h: h - 28 };
      const maxY = niceMax(Math.max(100, ...tl.map((p) => Math.max(p[1], p[2]))) * 1.1);
      const x = (i) => box.x + (box.w * (i + (N - tl.length))) / (N - 1);
      const y = (v) => box.y + box.h - (Math.min(v, maxY) / maxY) * box.h;
      const tEnd = state.bus_time;
      const labels = [];
      for (let s = 0; s <= 60; s += 10) labels.push([box.x + box.w * (1 - s / 60), s === 0 ? "now" : `-${s}s`]);
      axes(ctx, box, maxY, 4, (v) => (v >= 1000 ? (v / 1000).toFixed(v % 1000 ? 1 : 0) + "k" : v.toFixed(0)), labels);
      if (tl.length > 1) {
        const normal = tl.map((p, i) => [x(i), y(Math.max(0, p[1] - p[5]))]);
        const total = tl.map((p, i) => [x(i), y(p[1])]);
        // attack band (between normal and total)
        ctx.fillStyle = hexA(css("--attack"), 0.35);
        ctx.beginPath();
        total.forEach(([a, b], i) => (i ? ctx.lineTo(a, b) : ctx.moveTo(a, b)));
        for (let i = normal.length - 1; i >= 0; i--) ctx.lineTo(normal[i][0], normal[i][1]);
        ctx.closePath(); ctx.fill();
        // normal area
        ctx.fillStyle = hexA(css("--normal"), 0.18);
        path(ctx, normal); ctx.lineTo(normal[normal.length - 1][0], box.y + box.h); ctx.lineTo(normal[0][0], box.y + box.h); ctx.closePath(); ctx.fill();
        ctx.strokeStyle = css("--normal"); ctx.lineWidth = 1.6; path(ctx, normal); ctx.stroke();
        ctx.strokeStyle = css("--attack"); ctx.lineWidth = 1.2; path(ctx, total); ctx.stroke();
        // flagged line
        ctx.strokeStyle = css("--flag"); ctx.lineWidth = 2; ctx.setLineDash([]);
        path(ctx, tl.map((p, i) => [x(i), y(p[2])])); ctx.stroke();
      }
      ctx.fillStyle = css("--muted"); ctx.textAlign = "left"; ctx.textBaseline = "top";
      ctx.fillText("frames / s", box.x + 4, box.y + 2);
      void tEnd;
    }
    // --- score ---
    {
      const { ctx, w, h } = setupCanvas($("chart-score"));
      const box = { x: 46, y: 8, w: w - 56, h: h - 16 };
      const lo = 0.3, hi = 0.9;
      const x = (i) => box.x + (box.w * (i + (N - tl.length))) / (N - 1);
      const y = (v) => box.y + box.h - ((Math.min(Math.max(v, lo), hi) - lo) / (hi - lo)) * box.h;
      // attack shading
      ctx.fillStyle = hexA(css("--attack"), 0.1);
      tl.forEach((p, i) => { if (p[5] > 0) ctx.fillRect(x(i) - box.w / (N - 1) / 2, box.y, box.w / (N - 1) + 0.5, box.h); });
      ctx.font = "11px " + css("--sans"); ctx.fillStyle = css("--muted"); ctx.strokeStyle = css("--grid");
      ctx.textAlign = "right"; ctx.textBaseline = "middle";
      for (const v of [0.3, 0.45, 0.6, 0.75, 0.9]) {
        const yy = Math.round(y(v)) + 0.5;
        ctx.beginPath(); ctx.moveTo(box.x, yy); ctx.lineTo(box.x + box.w, yy); ctx.stroke();
        ctx.fillText(v.toFixed(2), box.x - 6, yy);
      }
      if (tl.length > 1) {
        ctx.strokeStyle = hexA(css("--score"), 0.45); ctx.lineWidth = 1;
        path(ctx, tl.map((p, i) => [x(i), y(p[4])])); ctx.stroke();
        ctx.strokeStyle = css("--score"); ctx.lineWidth = 2;
        path(ctx, tl.map((p, i) => [x(i), y(p[3])])); ctx.stroke();
      }
      const ty = Math.round(y(state.threshold)) + 0.5;
      ctx.strokeStyle = css("--text"); ctx.setLineDash([4, 3]); ctx.lineWidth = 1.2;
      ctx.beginPath(); ctx.moveTo(box.x, ty); ctx.lineTo(box.x + box.w, ty); ctx.stroke(); ctx.setLineDash([]);
      ctx.fillStyle = css("--text"); ctx.textAlign = "left"; ctx.textBaseline = "bottom";
      ctx.fillText(`threshold ${state.threshold.toFixed(3)}`, box.x + 4, ty - 2);
      ctx.fillStyle = css("--muted"); ctx.textBaseline = "top";
      ctx.fillText("anomaly score (peak / mean)", box.x + 4, box.y + 2);
    }
  }

  function drawHist() {
    if (!state) return;
    const { ctx, w, h } = setupCanvas($("chart-hist"));
    const box = { x: 12, y: 16, w: w - 24, h: h - 36 };
    const n = state.hist.normal, a = state.hist.attack;
    const bins = n.length;
    const lo = 0.3, hi = 0.9;
    const b0 = Math.floor(lo * bins), b1 = Math.ceil(hi * bins);
    const sum = (arr) => arr.reduce((s, v) => s + v, 0) || 1;
    const sn = sum(n), sa = sum(a);
    const dn = n.map((v) => v / sn), da = a.map((v) => v / sa);
    const maxD = Math.max(1e-9, ...dn.slice(b0, b1), ...da.slice(b0, b1));
    const bw = box.w / (b1 - b0);
    for (let i = b0; i < b1; i++) {
      const xx = box.x + (i - b0) * bw;
      const hn = (dn[i] / maxD) * box.h, ha = (da[i] / maxD) * box.h;
      ctx.fillStyle = hexA(css("--normal"), 0.6); ctx.fillRect(xx + 1, box.y + box.h - hn, bw / 2 - 1, hn);
      ctx.fillStyle = hexA(css("--attack"), 0.7); ctx.fillRect(xx + bw / 2, box.y + box.h - ha, bw / 2 - 1, ha);
    }
    ctx.strokeStyle = css("--line"); ctx.beginPath(); ctx.moveTo(box.x, box.y + box.h + 0.5); ctx.lineTo(box.x + box.w, box.y + box.h + 0.5); ctx.stroke();
    const tx = box.x + ((state.threshold - lo) / (hi - lo)) * box.w;
    ctx.strokeStyle = css("--text"); ctx.setLineDash([4, 3]); ctx.beginPath(); ctx.moveTo(tx, box.y - 4); ctx.lineTo(tx, box.y + box.h); ctx.stroke(); ctx.setLineDash([]);
    ctx.font = "11px " + css("--sans"); ctx.fillStyle = css("--muted"); ctx.textBaseline = "top";
    ctx.textAlign = "left"; ctx.fillText(lo.toFixed(1), box.x, box.y + box.h + 4);
    ctx.textAlign = "right"; ctx.fillText(hi.toFixed(1), box.x + box.w, box.y + box.h + 4);
    ctx.textAlign = "center"; ctx.fillText("anomaly score distribution · normal vs attack", box.x + box.w / 2, box.y + box.h + 4);
    ctx.textBaseline = "bottom"; ctx.fillStyle = css("--text"); ctx.fillText("threshold", tx, box.y - 4);
  }

  function hexA(color, alpha) {
    const m = color.match(/^#([0-9a-f]{6})$/i);
    if (!m) return color;
    const n = parseInt(m[1], 16);
    return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${alpha})`;
  }

  // ------------------------------------------------------------ renderers
  function renderStatus() {
    const s = state.status;
    const el = $("status");
    el.className = "status " + (s === "UNDER ATTACK" ? "status-attack" : s === "WARNING" ? "status-warning" : "status-secure");
    $("status-text").textContent = s === "SECURE" ? "BUS SECURE" : s;
    document.body.classList.toggle("under-attack", s === "UNDER ATTACK");
    $("bus-time").textContent = state.bus_time.toFixed(1);
    $("source").textContent = state.source;
    $("btn-pause").textContent = state.paused ? "▶ Resume" : "⏸ Pause";
    document.title = (s === "UNDER ATTACK" ? "🚨 " : s === "WARNING" ? "⚠ " : "") + "EV CAN IDS · Live Monitor";
  }

  function renderKpis() {
    const k = state.kpi, m = state.metrics;
    $("k-fps").textContent = fmtInt(Math.round(k.fps));
    $("k-total").textContent = fmtInt(k.total_frames);
    $("k-ids").textContent = `${k.unique_ids} IDs seen · ${k.unknown_ids} unknown`;
    $("k-flagged").textContent = fmtInt(Math.round(k.flagged_ps));
    $("k-incidents").textContent = k.active_incidents;
    $("k-inc-total").textContent = `${k.incidents_total} total`;
    $("kpi-incidents").classList.toggle("hot", k.active_incidents > 0);
    $("k-recall").textContent = m.labelled ? pct(m.recall) : "n/a";
    $("k-fpr").textContent = m.labelled ? pct(m.fpr, 2) : "n/a";
    $("k-lat").textContent = k.us_per_frame ? k.us_per_frame.toFixed(0) : "–";
    $("k-cap").textContent = k.capacity_fps ? `µs / frame · ${fmtInt(k.capacity_fps)} fps capacity` : "µs / frame";
    $("model-info").textContent = `Model: ${state.model.trees} trees · trained on ${fmtInt(state.model.n_train)} normal frames (${state.model.source}) · ${state.model.known_ids} known IDs · calibrated threshold ${state.model.threshold.toFixed(3)} @ ${(state.model.target_fpr * 100).toFixed(1)}% target FPR`;
  }

  function renderQuality() {
    const m = state.metrics;
    $("q-hint").textContent = m.labelled ? "frame-level, ground truth from injector" : "no ground truth for this source";
    for (const k of ["tn", "fp", "fn", "tp"]) $("cm-" + k).textContent = m.labelled ? fmtInt(m[k]) : "–";
    $("m-acc").textContent = pct(m.accuracy, 2);
    $("m-prec").textContent = pct(m.precision, 2);
    $("m-rec").textContent = pct(m.recall, 2);
    $("m-f1").textContent = m.f1 == null ? "–" : m.f1.toFixed(3);
    const d = state.detectors;
    $("m-by").textContent = `ML ${fmtInt(d.ML)} · rules ${fmtInt(d.RULE)} · both ${fmtInt(d["ML+RULE"])}`;
    document.querySelectorAll("#mode button").forEach((b) => b.classList.toggle("on", b.dataset.m === state.mode));
    const pa = Object.entries(m.per_attack);
    $("per-attack").innerHTML = pa.length
      ? pa.map(([k, v]) => `<div class="pa"><span>${esc(k)}</span><span class="bar"><i style="width:${((v.recall || 0) * 100).toFixed(1)}%"></i></span><span>${pct(v.recall, 0)}</span></div>`).join("")
      : `<div class="hint">Per-attack detection appears after the first attack.</div>`;
    const thr = $("thr");
    if (document.activeElement !== thr) thr.value = state.threshold;
    $("thr-out").textContent = state.threshold.toFixed(3);
  }

  function incidentHTML(inc) {
    const where = inc.ecu ? `${inc.key} · ${esc(inc.ecu)}` : inc.can_ids.slice(0, 4).join(" ") + (inc.can_ids.length > 4 ? " …" : "");
    const why = (inc.explanation || []).map((e) => e.rule
      ? `<span class="chip rule" title="specification rule">⚑ ${esc(e.label)}${e.value ? ` <b>${esc(e.value)}</b> vs ${esc(e.normal)}` : ""}</span>`
      : `<span class="chip" title="robust z-score ${e.z}">${esc(e.label)} <b>${esc(e.value)}</b> vs ${esc(e.normal)}</span>`).join("");
    const isNew = !seenIncidents.has(inc.id);
    return `<article class="alert sev-${inc.severity} ${inc.status === "ACTIVE" ? "active" : ""} ${inc.acknowledged ? "acked" : ""} ${isNew && !firstPayload ? "new" : ""}" data-id="${inc.id}">
      <div class="a-top">
        <span class="sev">${inc.severity}</span>
        <span class="a-name">#${inc.id} ${esc(inc.title)}</span>
        <span class="a-where">${where}</span>
        <span class="a-state ${inc.status}">${inc.status === "ACTIVE" ? "● ACTIVE" : "✓ RESOLVED"}</span>
      </div>
      <div class="a-stats">
        <span>t=<b>${inc.first_seen.toFixed(1)}s</b></span>
        <span>duration <b>${inc.duration.toFixed(1)}s</b></span>
        <span>frames <b>${fmtInt(inc.frames)}</b></span>
        <span>peak <b>${fmtInt(Math.round(inc.peak_rate))}/s</b></span>
        <span>score <b>${inc.peak_score.toFixed(3)}</b></span>
      </div>
      ${why ? `<div class="a-why">${why}</div>` : ""}
      <div class="a-action">${esc(inc.action)}</div>
      ${inc.acknowledged ? "" : `<div class="a-foot"><button class="btn small ghost" data-ack="${inc.id}">✓ Acknowledge</button></div>`}
    </article>`;
  }

  function renderAlerts() {
    const list = state.incidents.filter((i) => alertFilter === "all" || (alertFilter === "active" ? i.status === "ACTIVE" : !i.acknowledged));
    const box = $("alerts");
    const unacked = state.incidents.filter((i) => !i.acknowledged).length;
    const badge = $("unacked");
    badge.textContent = unacked; badge.classList.toggle("zero", unacked === 0);
    // New incidents -> toast + sound.
    for (const inc of state.incidents) {
      if (!seenIncidents.has(inc.id) && !firstPayload && inc.status === "ACTIVE") toast(inc);
    }
    const scroll = box.scrollTop;
    box.innerHTML = list.length ? list.map(incidentHTML).join("") :
      `<div class="empty">${state.incidents.length ? "No incidents match this filter." : "No incidents yet. The bus is clean — launch an attack to see detection in action."}</div>`;
    box.scrollTop = scroll;
    state.incidents.forEach((i) => seenIncidents.add(i.id));
  }

  function toast(inc) {
    beep(inc.severity);
    const el = document.createElement("div");
    el.className = `toast sev-${inc.severity}`;
    const where = inc.ecu ? `${inc.key} (${inc.ecu})` : inc.can_ids.slice(0, 3).join(", ");
    el.innerHTML = `<span class="sev">${inc.severity}</span><b>${esc(inc.title)}</b><p>${esc(where)} · ${fmtInt(inc.frames)} frames · score ${inc.peak_score.toFixed(3)}</p>`;
    $("toasts").prepend(el);
    setTimeout(() => el.remove(), 6000);
    while ($("toasts").children.length > 4) $("toasts").lastChild.remove();
  }

  function renderIds() {
    const rows = state.ids.map((r) => {
      const hot = r.expected_rate && r.rate > r.expected_rate * 1.6;
      const sc = Math.max(0, Math.min(1, (r.last_score - 0.3) / 0.6));
      const color = r.last_score >= state.threshold ? css("--bad") : css("--good");
      return `<tr class="${r.flagged && r.last_score >= state.threshold ? "bad" : ""} ${r.known ? "" : "unknown"} ${r.active ? "" : "idle"}">
        <td class="mono">${r.id}</td>
        <td>${r.known ? esc(r.name) : `<span class="tag new">UNKNOWN</span> ${esc(r.name)}`}</td>
        <td class="num mono ${hot ? "rate-hot" : ""}">${r.rate.toFixed(0)}</td>
        <td class="num mono">${r.expected_rate == null ? "–" : r.expected_rate.toFixed(0)}</td>
        <td class="num mono">${fmtInt(r.count)}</td>
        <td class="num mono">${fmtInt(r.flagged)}</td>
        <td><span class="sbar"><i style="width:${(sc * 100).toFixed(0)}%;background:${color}"></i></span> <span class="mono">${r.last_score.toFixed(2)}</span></td>
        <td class="mono">${esc(r.data)}</td>
      </tr>`;
    }).join("");
    $("ids-body").innerHTML = rows;
    // impersonation targets
    const sel = $("target");
    const known = state.ids.filter((r) => r.known);
    let changed = false;
    for (const r of known) if (!targetsFilled.has(r.id)) { targetsFilled.add(r.id); changed = true; }
    if (changed) {
      const cur = sel.value || "0x0B4";
      const opts = [...targetsFilled].sort();
      const names = Object.fromEntries(known.map((r) => [r.id, r.name]));
      sel.innerHTML = opts.map((id) => `<option value="${id}">${id}${names[id] ? " · " + esc(names[id]) : ""}</option>`).join("");
      sel.value = opts.includes(cur) ? cur : opts[0];
    }
  }

  function renderFrames() {
    const only = $("only-flagged").checked;
    const frames = state.recent.filter((f) => !only || f.flagged).slice(0, 40);
    $("frames").innerHTML = frames.map((f) => `<div class="fr ${f.flagged ? "flag" : ""}">
      <span class="t">${f.t.toFixed(4)}</span><span>${f.id}</span><span>[${f.dlc}]</span><span>${f.data}</span>
      <span>${f.score.toFixed(3)}</span><span class="cat" title="${f.flagged ? "detected by " + esc(f.detector) : ""}">${f.flagged ? esc(f.category) + ` <small>${esc(f.detector)}</small>` : ""}</span></div>`).join("")
      || `<div class="empty">No flagged frames in the last window.</div>`;
    const atks = state.attacks;
    $("active-attacks").innerHTML = atks.map((a) => `<div class="active-attack"><span>● ${a.kind.toUpperCase()}${a.target ? " → " + a.target : ""}</span><span>${fmtInt(a.sent)} frames · ${a.remaining.toFixed(1)}s left</span></div>`).join("");
    document.querySelectorAll(".attack-btn").forEach((b) => b.classList.toggle("running", atks.some((a) => a.kind === b.dataset.kind)));
    $("events").innerHTML = state.events.map((e) => `<li class="${e.kind}"><b>${e.t.toFixed(1)}s</b>${esc(e.text)}</li>`).join("") || `<li>Monitoring started.</li>`;
  }

  function render() {
    renderStatus(); renderKpis(); renderAlerts(); renderQuality(); renderIds(); renderFrames();
    drawTimeline(); drawHist();
    firstPayload = false;
  }

  // ------------------------------------------------------------ stream
  function connect() {
    const es = new EventSource("/api/stream");
    es.onmessage = (ev) => { state = JSON.parse(ev.data); render(); };
    es.onerror = () => {
      const el = $("status");
      el.className = "status status-offline";
      $("status-text").textContent = "RECONNECTING…";
    };
  }

  // ------------------------------------------------------------ controls
  document.querySelectorAll(".attack-btn").forEach((b) => b.addEventListener("click", () => {
    const body = { kind: b.dataset.kind, duration: +$("duration").value };
    if (b.dataset.kind === "impersonation") body.target = $("target").value;
    post("/api/attack", body);
  }));
  $("duration").addEventListener("input", (e) => ($("dur-out").textContent = e.target.value + " s"));
  $("btn-stop").addEventListener("click", () => post("/api/attack/stop"));
  $("btn-pause").addEventListener("click", () => post("/api/control", { action: state && state.paused ? "resume" : "pause" }));
  $("speed").addEventListener("change", (e) => post("/api/control", { action: "speed", value: +e.target.value }));
  $("btn-reset").addEventListener("click", () => { seenIncidents.clear(); firstPayload = true; post("/api/control", { action: "reset" }); });
  $("btn-sound").addEventListener("click", (e) => {
    soundOn = !soundOn; store.set("sound", soundOn);
    e.currentTarget.setAttribute("aria-pressed", String(soundOn));
    if (soundOn) beep("LOW");
  });
  $("btn-theme").addEventListener("click", () => {
    const t = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = t; store.set("theme", t);
    drawTimeline(); drawHist();
  });
  let thrTimer = null;
  $("thr").addEventListener("input", (e) => {
    $("thr-out").textContent = (+e.target.value).toFixed(3);
    clearTimeout(thrTimer);
    thrTimer = setTimeout(() => post("/api/threshold", { value: +e.target.value }), 150);
  });
  $("btn-thr-reset").addEventListener("click", () => post("/api/threshold", { reset: true }));
  $("alerts").addEventListener("click", (e) => {
    const id = e.target.closest("[data-ack]")?.dataset.ack;
    if (id) post(`/api/incidents/${id}/ack`);
  });
  $("btn-ack-all").addEventListener("click", () => post("/api/incidents/ack-all"));
  $("alert-filter").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    alertFilter = b.dataset.f;
    document.querySelectorAll("#alert-filter button").forEach((x) => x.classList.toggle("on", x === b));
    if (state) renderAlerts();
  });
  $("mode").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    post("/api/control", { action: "mode", value: b.dataset.m });
  });
  $("only-flagged").addEventListener("change", () => state && renderFrames());
  $("btn-scenario").addEventListener("click", () => {
    const speed = (state && state.speed) || 1;
    const steps = [["dos", 0, {}], ["fuzzy", 20, {}], ["impersonation", 40, { target: "0x0B4" }]];
    steps.forEach(([kind, at, extra]) => setTimeout(() => post("/api/attack", { kind, duration: 8, ...extra }), (at * 1000) / speed));
  });
  window.addEventListener("resize", () => { drawTimeline(); drawHist(); });

  connect();
})();
