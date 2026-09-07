"""The diffusion transform must change density and nothing else.

Experiment 10 uses this to decide whether the project's headline claim survives
low-rate attacks, so the transform itself needs to be above suspicion. If it
quietly altered flow features, dropped rows, or moved benign traffic, the sweep
would measure the bug instead of the density.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from ekagra.ingest.diffuse import DiffusionConfig, diffuse_attacks


def make_corpus(n_benign: int = 8000, n_attack: int = 2000,
                n_hosts: int = 25, span_s: float = 6000.0) -> pd.DataFrame:
    """A small corpus with a bursty attack, shaped like the real one.

    Benign traffic is spread across the whole span so hosts qualify as blend
    targets; the attack is concentrated at the start, which is the arrangement
    the transform exists to break up.
    """
    rng = np.random.default_rng(7)
    t0 = pd.Timestamp("2017-07-03 09:00:00")

    benign = pd.DataFrame({
        "Timestamp": t0 + pd.to_timedelta(rng.random(n_benign) * span_s, unit="s"),
        "Src IP": [f"192.168.10.{5 + i % n_hosts}" for i in range(n_benign)],
        "Dst IP": [f"10.0.0.{rng.integers(1, 50)}" for _ in range(n_benign)],
        "Dst Port": rng.integers(1, 65535, n_benign),
        "Total Fwd Packet": rng.integers(1, 40, n_benign).astype(float),
        "Total Length of Fwd Packet": rng.integers(40, 8000, n_attack + n_benign)[:n_benign].astype(float),
        "Label": "BENIGN",
    })
    # One campaign from one external address, packed into the first 200s.
    attack = pd.DataFrame({
        "Timestamp": t0 + pd.to_timedelta(rng.random(n_attack) * 200.0, unit="s"),
        "Src IP": "172.16.0.1",
        "Dst IP": [f"10.0.0.{rng.integers(1, 50)}" for _ in range(n_attack)],
        "Dst Port": rng.integers(1, 65535, n_attack),
        "Total Fwd Packet": rng.integers(1, 5, n_attack).astype(float),
        "Total Length of Fwd Packet": rng.integers(40, 200, n_attack).astype(float),
        "Label": "PortScan",
    })
    df = pd.concat([benign, attack], ignore_index=True)
    df["Timestamp"] = df["Timestamp"].astype("datetime64[us]")
    return df.sort_values("Timestamp").reset_index(drop=True)


def cell_counts(df: pd.DataFrame, window_s: float = 60.0) -> pd.DataFrame:
    t0 = df["Timestamp"].min()
    w = np.floor((df["Timestamp"] - t0).dt.total_seconds() / window_s)
    return pd.DataFrame({"src": df["Src IP"].to_numpy(), "w": w.to_numpy(),
                         "atk": (df["Label"] != "BENIGN").to_numpy()})


def test_rows_and_labels_are_preserved():
    """Diffusion rearranges; it must not add, drop or relabel anything."""
    df = make_corpus()
    out, _ = diffuse_attacks(df, DiffusionConfig(flows_per_cell=4.0))
    assert len(out) == len(df)
    assert out["Label"].value_counts().to_dict() == df["Label"].value_counts().to_dict()


def test_per_flow_features_are_untouched():
    """The whole argument rests on flow features being the real ones."""
    df = make_corpus()
    out, _ = diffuse_attacks(df, DiffusionConfig(flows_per_cell=4.0))
    for col in ("Total Fwd Packet", "Total Length of Fwd Packet", "Dst Port"):
        before = np.sort(df[col].to_numpy())
        after = np.sort(out[col].to_numpy())
        assert np.array_equal(before, after), f"{col} changed"


def test_benign_traffic_does_not_move():
    """The background must stay the capture's own, in time and in address."""
    df = make_corpus()
    out, _ = diffuse_attacks(df, DiffusionConfig(flows_per_cell=2.0))
    b_in = df[df["Label"] == "BENIGN"].sort_values(["Timestamp", "Dst Port"])
    b_out = out[out["Label"] == "BENIGN"].sort_values(["Timestamp", "Dst Port"])
    assert np.array_equal(b_in["Timestamp"].to_numpy(), b_out["Timestamp"].to_numpy())
    assert np.array_equal(b_in["Src IP"].to_numpy(), b_out["Src IP"].to_numpy())


@pytest.mark.parametrize("target", [32.0, 8.0, 1.0])
def test_realised_density_tracks_the_target(target):
    """The knob has to actually turn.

    Cells are allocated as ceil(n / target), so the realised density is at most
    the target, short of it by that rounding - negligible once a campaign is
    much larger than the target it is being spread to.
    """
    df = make_corpus()
    out, stats = diffuse_attacks(df, DiffusionConfig(flows_per_cell=target))
    realised = stats["realised_flows_per_cell"]
    assert stats["density_achieved"], f"pool too small: {stats['starved_campaigns']}"
    assert 0.9 * target <= realised <= target + 1.5, \
        f"asked {target}, realised {realised}"


def test_dilution_falls_as_attacks_spread():
    """The variable that actually explains the result: as a campaign spreads,
    attack flows become a smaller share of the cells they land in."""
    df = make_corpus()
    dil, realised = [], []
    for d in (32.0, 8.0, 1.0):
        _, s = diffuse_attacks(df, DiffusionConfig(flows_per_cell=d))
        dil.append(s["dilution"])
        realised.append(s["realised_flows_per_cell"])
    assert realised[0] > realised[1] > realised[2], \
        f"density not monotone: {realised}"
    assert dil[0] > dil[1] > dil[2], f"dilution not monotone: {dil}"


def test_blending_puts_attacks_on_hosts_that_carry_benign_traffic():
    """Without this the attacker's cells are pure attack and the density knob
    measures nothing - the point is argued in the module docstring."""
    df = make_corpus()
    out, _ = diffuse_attacks(df, DiffusionConfig(flows_per_cell=1.0))
    atk_hosts = set(out.loc[out["Label"] != "BENIGN", "Src IP"])
    benign_hosts = set(out.loc[out["Label"] == "BENIGN", "Src IP"])
    assert atk_hosts <= benign_hosts
    assert "172.16.0.1" not in atk_hosts

    cells = cell_counts(out)
    g = cells.groupby(["src", "w"])["atk"].agg(["sum", "count"])
    hot = g[g["sum"] > 0]
    mixed = (hot["count"] > hot["sum"]).mean()
    assert mixed > 0.5, f"only {mixed:.2f} of attack cells contain benign flows"


def test_blending_can_be_switched_off():
    df = make_corpus()
    out, stats = diffuse_attacks(
        df, DiffusionConfig(flows_per_cell=4.0, blend_hosts=False))
    assert set(out.loc[out["Label"] != "BENIGN", "Src IP"]) == {"172.16.0.1"}
    assert stats["blend_hosts"] is False


def test_deterministic_for_a_seed():
    df = make_corpus()
    a, sa = diffuse_attacks(df, DiffusionConfig(flows_per_cell=4.0, seed=3))
    b, sb = diffuse_attacks(df, DiffusionConfig(flows_per_cell=4.0, seed=3))
    assert sa == sb
    assert np.array_equal(a["Timestamp"].to_numpy(), b["Timestamp"].to_numpy())
    assert np.array_equal(a["Src IP"].to_numpy(), b["Src IP"].to_numpy())


def test_different_seeds_give_different_arrangements():
    df = make_corpus()
    a, _ = diffuse_attacks(df, DiffusionConfig(flows_per_cell=4.0, seed=1))
    b, _ = diffuse_attacks(df, DiffusionConfig(flows_per_cell=4.0, seed=2))
    assert not np.array_equal(a["Timestamp"].to_numpy(), b["Timestamp"].to_numpy())


def test_refuses_a_corpus_with_no_attacks():
    df = make_corpus()
    benign_only = df[df["Label"] == "BENIGN"].copy()
    with pytest.raises(ValueError, match="no attack rows"):
        diffuse_attacks(benign_only, DiffusionConfig(flows_per_cell=4.0))


def test_timestamp_dtype_survives():
    """pandas 3 refuses a [ns] value assigned into a [us] column, and the
    corpus is [us]."""
    df = make_corpus()
    out, _ = diffuse_attacks(df, DiffusionConfig(flows_per_cell=4.0))
    assert out["Timestamp"].dtype == df["Timestamp"].dtype
    assert out["Timestamp"].is_monotonic_increasing


def test_hiding_in_traffic_lowers_dilution():
    """The mechanism that actually reaches a diluted cell.

    Benign traffic is concentrated in time, so a uniformly-placed attack flow
    usually lands in a window where its host did nothing else - alone in the
    cell rather than hidden in it. Weighting placement by the host's activity
    is what models an adversary running inside the victim's own noise.
    """
    df = make_corpus()
    _, spread = diffuse_attacks(
        df, DiffusionConfig(flows_per_cell=1.0, hide_in_traffic=False))
    _, hidden = diffuse_attacks(
        df, DiffusionConfig(flows_per_cell=1.0, hide_in_traffic=True))
    assert hidden["dilution"] < spread["dilution"], (
        f"hiding did not dilute: {hidden['dilution']:.3f} "
        f"vs {spread['dilution']:.3f}")
    assert hidden["benign_per_attack_cell"] > spread["benign_per_attack_cell"]


def test_hiding_does_not_change_the_flow_count_per_cell():
    """Placement changes which cells are used, not how many flows go in them."""
    df = make_corpus()
    _, spread = diffuse_attacks(
        df, DiffusionConfig(flows_per_cell=8.0, hide_in_traffic=False))
    _, hidden = diffuse_attacks(
        df, DiffusionConfig(flows_per_cell=8.0, hide_in_traffic=True))
    assert abs(hidden["realised_flows_per_cell"]
               - spread["realised_flows_per_cell"]) < 1.0
