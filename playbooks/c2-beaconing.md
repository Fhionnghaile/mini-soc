# IR playbook - regular C2 beaconing

**Triage.** Confirm the alert: correlate the detection event(s) with the labelled timestamp; rule out
known-good automation. Record `detect_time`.

**Contain.** Isolate the actor/host (disable the account / network-quarantine the host). Mark the
contain step done -> this logs `contain_time` (feeds MTTR).

**Eradicate.** Remove persistence, rotate exposed credentials/keys, close the exploited path.

**Recover.** Restore access under monitoring; verify the detection no longer fires.

**Review.** Post-incident: was MTTD/MTTR within target? Tune the rule; add a detection unit test for
any gap found.
