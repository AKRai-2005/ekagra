"""Evidence-chain invariants.

The whole value of the evidence layer is that alteration is detectable. These
tests attack the log the way an adversary would - edit a value, delete an
entry, reorder two, swap a feature vector, forge without the key - and assert
that verification catches each one.
"""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ekagra.evidence.bundle import (  # noqa: E402
    GENESIS, EvidenceLog, canonical_features, feature_digest, model_digest,
)

KEY = b"enclave-demo-key"


def make_log(n=6, key=KEY) -> EvidenceLog:
    log = EvidenceLog(key=key, model_hash=model_digest("test-model", 1))
    for i in range(n):
        log.append(
            alert_id=f"a{i:03d}", ts=1000.0 + i, window=i // 2,
            host=f"10.20.30.{10 + i}",
            threat_class="scan" if i % 2 else "ddos",
            score=0.5 + i / 100, confidence=0.8,
            decision="ALERT" if i % 3 else "ABSTAIN",
            features={"hw_src_n_peers": float(i), "hw_dst_src_entropy": 1.5 + i},
            observed={"window": i // 2, "flows": [i, i + 1]},
            decision_path=[f"rule{i}"],
        )
    return log


def test_intact_log_verifies():
    log = make_log()
    assert log.verify() == []
    assert log.bundles[0].prev_hash == GENESIS


def test_each_entry_links_to_the_previous():
    log = make_log()
    for prev, cur in zip(log.bundles, log.bundles[1:]):
        assert cur.prev_hash == prev.entry_hash


def test_editing_a_value_is_detected():
    """An in-place edit must break that entry and every entry after it."""
    log = make_log()
    log.bundles[2].score = 0.99
    problems = log.verify()
    assert any("seq 2" in p and "altered" in p for p in problems)
    # the chain from 3 onward still links to the *old* hash, so 3 breaks too
    assert any("seq 3" in p and "broken link" in p for p in problems)


def test_deleting_an_entry_is_detected():
    log = make_log()
    del log.bundles[3]
    problems = log.verify()
    assert any("broken link" in p for p in problems), \
        "deleting an entry should orphan the next one"


def test_reordering_is_detected():
    log = make_log()
    log.bundles[1], log.bundles[2] = log.bundles[2], log.bundles[1]
    assert any("broken link" in p for p in log.verify())


def test_swapping_a_feature_vector_is_detected():
    """The feature digest commits to the vector, so substituting one is caught
    even though the vector itself is not in the hashed field list."""
    log = make_log()
    log.bundles[1].features["hw_src_n_peers"] = 999.0
    problems = log.verify()
    assert any("seq 1" in p and "feature vector" in p for p in problems)


def test_forgery_without_the_key_fails_hmac():
    """An attacker who rewrites the whole chain produces valid hashes - the
    HMAC is what stops that."""
    log = make_log()
    log.bundles[2].score = 0.42
    # Recompute hashes forward, as a competent attacker would.
    prev = GENESIS
    for b in log.bundles:
        b.prev_hash = prev
        b.entry_hash = b.compute_hash()
        prev = b.entry_hash
    # Hash chain now self-consistent...
    assert not any("broken link" in p or "altered" in p for p in log.verify(key=b""))
    # ...but the HMACs were not regenerated, because the key is unknown.
    assert any("HMAC" in p for p in log.verify(key=KEY))


def test_canonical_form_is_order_independent():
    a = {"b": 2.0, "a": 1.0}
    b = {"a": 1.0, "b": 2.0}
    assert canonical_features(a) == canonical_features(b)
    assert feature_digest(a) == feature_digest(b)


def test_canonical_form_is_fixed_precision():
    """Float repr differences must not change a digest - this is why values are
    rendered at fixed precision rather than with str()."""
    assert feature_digest({"x": 0.1 + 0.2}) == feature_digest({"x": 0.3})


def test_negative_zero_hashes_like_zero():
    """Cross-language canonicalisation: Python renders -0.0 as "-0.000000",
    JavaScript's toFixed(6) as "0.000000". A Shannon entropy of exactly zero
    yields -0.0, so this really occurs - and it made the browser verifier
    report tampering that had not happened."""
    assert feature_digest({"x": -0.0}) == feature_digest({"x": 0.0})
    assert "-0.000000" not in canonical_features({"x": -0.0})


def test_non_finite_values_do_not_leak_into_the_digest():
    """inf renders as "inf" in Python and "Infinity" in JavaScript."""
    assert feature_digest({"x": float("inf")}) == feature_digest({"x": 0.0})
    assert feature_digest({"x": float("nan")}) == feature_digest({"x": 0.0})


def test_model_digest_changes_with_configuration():
    assert model_digest("m", 1) != model_digest("m", 2)
    assert model_digest("m", 1) == model_digest("m", 1)


def test_roundtrip_through_jsonl(tmp_path):
    log = make_log()
    p = tmp_path / "evidence.jsonl"
    log.write_jsonl(p)
    back = EvidenceLog.read_jsonl(p, key=KEY)
    assert len(back.bundles) == len(log.bundles)
    assert back.verify() == []
    assert back.head == log.head


def test_tampering_survives_a_roundtrip_and_is_still_caught(tmp_path):
    log = make_log()
    p = tmp_path / "evidence.jsonl"
    log.write_jsonl(p)
    import json
    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[2])          # parse rather than string-replace: the
    rec["threat_class"] = "benign"      # class at seq 2 is not what a literal
    lines[2] = json.dumps(rec, sort_keys=True)   # replace assumed it was
    p.write_text("\n".join(lines), encoding="utf-8")
    back = EvidenceLog.read_jsonl(p, key=KEY)
    assert back.verify(), "edit made on disk should be detected on reload"


def test_summary_counts():
    log = make_log(n=9)
    s = log.summary()
    assert s["entries"] == 9
    assert s["alerts"] + s["abstentions"] == 9
    assert sum(s["by_class"].values()) == s["alerts"]
