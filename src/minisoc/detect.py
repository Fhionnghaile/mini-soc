"""Detections. Each returns the timestamp it first fires on a stream, or None.
Each is independently unit-tested (sample events -> match / no-match)."""
from __future__ import annotations
from collections import defaultdict, deque

def brute_force(events, *, count=5, within=60):
    win = defaultdict(deque)
    for e in events:
        if e.get("type") == "login" and e.get("result") == "fail":
            a = e["actor"]; q = win[a]; q.append(e["ts"])
            while q and q[0] <= e["ts"] - within:
                q.popleft()
            if len(q) >= count:
                return e["ts"]
    return None

def self_priv_esc(events):
    for e in events:
        if (e.get("type") == "iam" and e.get("action") == "grant"
                and e.get("role") in ("admin", "owner") and e.get("grantee") == e.get("actor")):
            return e["ts"]
    return None

def beaconing(events, *, min_hits=6, jitter=5):
    hits = defaultdict(list)
    for e in events:
        if e.get("type") == "netflow":
            hits[(e["actor"], e["dst"])].append(e["ts"])
    for ts in hits.values():
        ts.sort()
        if len(ts) >= min_hits:
            gaps = [b - a for a, b in zip(ts, ts[1:])]
            med = sorted(gaps)[len(gaps)//2]
            if med > 0 and all(abs(g - med) <= jitter for g in gaps):
                return ts[min_hits-1]
    return None

def data_staging(events, *, threshold=100_000_000, within=60):
    win = defaultdict(deque)
    totals = defaultdict(int)
    for e in events:
        if e.get("type") == "netflow" and e.get("bytes", 0) > 0 and e.get("dst"):
            a = e["actor"]; q = win[a]
            q.append((e["ts"], e["bytes"])); totals[a] += e["bytes"]
            while q and q[0][0] <= e["ts"] - within:
                _, b = q.popleft(); totals[a] -= b
            if totals[a] >= threshold:
                return e["ts"]
    return None

RULES = {
    "brute-force": brute_force,
    "self-privilege-escalation": self_priv_esc,
    "c2-beaconing": beaconing,
    "data-staging": data_staging,
}

def run_all(events) -> dict[str, int]:
    """Return {rule_name: detect_ts} for rules that fired."""
    out = {}
    for name, fn in RULES.items():
        ts = fn(events)
        if ts is not None:
            out[name] = ts
    return out
