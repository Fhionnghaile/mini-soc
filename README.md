# Mini-SOC in a box

<!-- at-a-glance -->
> **Detection measured by whether it actually detects — precision and recall, not alert volume.**  
> **Result:** 3 suites; precision = recall = 1.0 on the labelled corpus.  
> **Reproduce:** `pytest -q`  
> ![CI](https://github.com/fhionnghaile/mini-soc/actions/workflows/ci.yml/badge.svg) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Fhionnghaile/mini-soc/badge)](https://scorecard.dev/viewer/?uri=github.com/Fhionnghaile/mini-soc)
>
> **What this is worth:** Shows detections that catch real attacks without drowning the team in false positives — the thing every SOC struggles with.


Reproducible **detection engineering**: generate labelled telemetry -> detect -> respond, with
**MTTD / MTTR** and **precision / recall** measured.

- **Telemetry** (`scenarios.py`): deterministic benign traffic plus injectable attacks
  (brute-force, self-privilege-escalation, C2 beaconing, data staging) with ground-truth timestamps.
- **Detections** (`detect.py`): four rules, each independently unit-tested (sample event -> match).
- **Metrics** (`metrics.py`): MTTD = detect-attack, MTTR = contain-detect, plus precision/recall over
  the labelled runs.
- **IR playbooks** (`playbooks/`): triage -> contain -> eradicate -> recover -> review per detection.

## Test it
```bash
PYTHONPATH=src pytest -q    # every attack fires its rule, benign stays quiet (precision=recall=1.0)
```

## Why it matters
This is a five-country SOC, productised and *measured* - detections you can prove, and MTTD/MTTR you
can put a number on. Rules have unit tests so they don't silently break.

## License
MIT.

## Key decisions

- Each detection a pure, unit-tested function, measured on labelled telemetry.
- MTTD/MTTR and precision/recall as the scoreboard, not alert count.
- IR playbooks per attack class, so an alert becomes an action.

## Scope & limits

- A labelled test corpus; real traffic has drift and novelty the metrics must be re-measured against.

