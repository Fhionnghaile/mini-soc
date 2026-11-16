"""Deterministic telemetry: benign traffic + injectable attacks with ground-truth labels."""
from __future__ import annotations
import random
from dataclasses import dataclass, field

@dataclass
class Run:
    scenario: str
    events: list[dict]
    attack_ts: int | None   # ground-truth attack time (None for benign)
    label: str              # which rule SHOULD fire ("" for benign)

def _benign(rng, start, n=40):
    ev=[]
    for i in range(n):
        ev.append({"ts": start + i*7, "type": "login", "actor": rng.choice(["alice","bob"]),
                   "result": "success", "dst": "", "bytes": rng.randint(100, 2000)})
    return ev

def generate(scenario: str, start: int = 1_000_000, seed: int = 0) -> Run:
    rng = random.Random(seed)
    ev = _benign(rng, start)
    if scenario == "benign":
        ev.sort(key=lambda e: e["ts"]); return Run(scenario, ev, None, "")
    at = start + 100
    if scenario == "brute_force":
        for i in range(6):
            ev.append({"ts": at + i*5, "type": "login", "actor": "mallory", "result": "fail", "dst": "", "bytes": 0})
        label = "brute-force"
    elif scenario == "priv_esc":
        ev.append({"ts": at, "type": "iam", "actor": "eve", "action": "grant", "role": "admin",
                   "grantee": "eve", "result": "success", "dst": "", "bytes": 0})
        label = "self-privilege-escalation"
    elif scenario == "beaconing":
        for i in range(8):
            ev.append({"ts": at + i*60, "type": "netflow", "actor": "host7", "dst": "198.51.100.9",
                       "result": "", "bytes": 512})
        label = "c2-beaconing"
    elif scenario == "data_staging":
        for i in range(5):
            ev.append({"ts": at + i*3, "type": "netflow", "actor": "dave", "dst": "203.0.113.5",
                       "result": "", "bytes": 60_000_000})
        label = "data-staging"
    else:
        raise ValueError(scenario)
    ev.sort(key=lambda e: e["ts"])
    return Run(scenario, ev, at, label)

ATTACKS = ["brute_force", "priv_esc", "beaconing", "data_staging"]
