# Presentation run-sheet (about 10 minutes)

## Before you start

```bash
pip install -r requirements.txt
python -m can_ids train --retrain        # fresh model (~4 s)
python -m can_ids dashboard --open
```

- Let the dashboard run for about 20 s before presenting, so the timeline is filled.
- On a projector, switch to the light theme (◐). Turn sound on (🔔) if the room has speakers.
- Backup if the browser misbehaves: `python -m can_ids monitor --demo` shows the same alerts in the terminal.
- Everything runs offline: there are no CDN or network dependencies.

## 1. The problem (1 min)

- CAN has **no authentication, no encryption and no integrity**. Any node can send any ID.
- In an EV, the same bus carries torque commands, BMS state and braking.
- Point at the **CAN ID monitor**: 14 ECUs, each with a fixed rate. That regularity is what the IDS learns.

## 2. Normal operation (1 min)

- Status **BUS SECURE**. The KPIs show roughly 470 frames/s analysed at about 250 µs per frame (>3,500 frames/s capacity).
- Trained **only on normal traffic**. No attack examples are needed, so it can catch attacks nobody has seen before.
- The footer shows the model: 200 trees, threshold calibrated for a 0.5 % false-positive target.

## 3. DoS attack (2 min)

- Press **DoS flood → Launch**.
- The status turns **UNDER ATTACK**, the red band appears on the timeline, and a CRITICAL toast and alarm fire.
- Open the alert card. It explains *why*: "CAN ID never seen in normal traffic", message frequency 1,000/s vs about 50, and burst size.
- Note the recommended action: rate-limit or block at the gateway.
- Thousands of malicious frames produce **one** incident. That is the alert manager at work.

## 4. Impersonation (2 min) — the hardest attack

- Target **0x0B4 · Motor inverter** → Launch.
- The attacker uses a *legitimate* ID, so no whitelist can catch it.
- Detected from behaviour: period 5 ms vs a learned 10 ms, and payload jumps (prediction error).
- In the CAN ID monitor, 0x0B4 shows rate **200 vs expected 100**.

## 5. Fuzzy (1 min)

- Launch **Fuzzy**. Hundreds of random IDs appear as UNKNOWN in the ID monitor.
- The frame log labels every flagged frame FUZZY and shows which detector caught it (ML, RULE or both).

## 6. Why hybrid? (2 min) — the research contribution

- Click **ML only** and launch DoS again: DoS recall drops to about 0 %.
- Explain the two limits of Isolation Forest:
  1. It cannot learn from features that are constant in normal data (e.g. "known ID").
  2. It does not rank values beyond the training range above the most extreme training point.
- Switch back to **Hybrid**: recall returns to 100 %.
- Show the table from `python -m can_ids evaluate`: F1 **26 % → 96 %**.
- Move the **threshold slider** to show the precision/recall trade-off live.

## 7. Operations (1 min)

- **Ack all** acknowledges alerts. **CSV** and **Report** export incidents for the SOC.
- Alerts also go to `logs/alerts.jsonl` (for SIEM ingestion) and optionally to Slack or Teams via `--webhook`.
- The same pipeline replays the real HCRL logs: `--replay data/DoS_attack_dataset.txt`.

## Likely questions

- **Why are there still false positives?** Most are genuine frames of the impersonated ECU. Its timing *is* disrupted, but frame-level labels call those frames normal. On clean traffic the FPR is about 0.5 %.
- **Why not a supervised model?** It needs labelled attacks and generalises poorly to new ones. This approach trains on normal data only.
- **Can it run in a car?** It keeps O(1) state per ID, and its rules are simple thresholds. The Isolation Forest (200 trees) is small enough for a gateway ECU; the Python prototype already processes 3,500+ frames/s.
- **What about the notebook's 59.5 % FPR?** That came from min-max normalising scores over the test set with a fixed 0.1 threshold. The streaming IDS calibrates the threshold on training data instead.
