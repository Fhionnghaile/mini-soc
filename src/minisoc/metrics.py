"""MTTD / MTTR and precision/recall over labelled runs."""
from __future__ import annotations

def mttd(attack_ts: int, detect_ts: int) -> int:
    return detect_ts - attack_ts

def mttr(detect_ts: int, contain_ts: int) -> int:
    return contain_ts - detect_ts

def evaluate(labelled):
    """labelled: list of (expected_label, fired_rules:set). Returns precision/recall over attack labels."""
    tp = fp = fn = 0
    for expected, fired in labelled:
        if expected:  # an attack run
            if expected in fired: tp += 1
            else: fn += 1
            fp += len(fired - {expected})
        else:         # benign run - any fire is a false positive
            fp += len(fired)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall}
