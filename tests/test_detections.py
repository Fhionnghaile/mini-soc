import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from minisoc import detect, metrics
from minisoc.scenarios import generate, ATTACKS

def test_each_attack_fires_its_rule_and_benign_is_quiet():
    labelled = []
    for sc in ATTACKS:
        run = generate(sc)
        fired = set(detect.run_all(run.events))
        assert run.label in fired, f"{sc} should fire {run.label}, got {fired}"
        labelled.append((run.label, fired))
    benign = generate("benign")
    bfired = set(detect.run_all(benign.events))
    assert bfired == set(), f"benign fired {bfired}"
    labelled.append(("", bfired))
    m = metrics.evaluate(labelled)
    assert m["precision"] == 1.0 and m["recall"] == 1.0, m

def test_mttd_mttr_math():
    assert metrics.mttd(1000, 1042) == 42
    assert metrics.mttr(1042, 1300) == 258

def test_rule_units():
    # brute force needs 5 within window; 4 is not enough
    four = [{"type":"login","result":"fail","actor":"x","ts":t} for t in range(0,20,5)]
    assert detect.brute_force(four) is None
    five = four + [{"type":"login","result":"fail","actor":"x","ts":20}]
    assert detect.brute_force(five) == 20
    # priv-esc: grant to someone else must NOT fire
    assert detect.self_priv_esc([{"type":"iam","action":"grant","role":"admin","grantee":"y","actor":"x","ts":1}]) is None
    assert detect.self_priv_esc([{"type":"iam","action":"grant","role":"admin","grantee":"x","actor":"x","ts":1}]) == 1
