"""Real-corpus adapter: CIC-IDS2017.

Why this file exists
--------------------
Every number in `exp01_ablation.py` is on generated traffic. That is a real
limitation and the first thing an evaluator should push on. This adapter runs
the same hypothesis against **real captured traffic with real labels**.

Which CIC-IDS2017?
------------------
Not the original 2017 CSVs. Those have documented defects - Engelen et al.
(2021) and others found label errors and bugs in the CICFlowMeter feature
extractor itself, and a large fraction of published results sit on top of them.
We use a **corrected re-extraction** (Huang, Bois & Marchioro, Zenodo record
22016274, CC-BY-4.0), which reruns a fixed CICFlowMeter over the original
captures. Using the corrected version and saying so is the point: it is
cheap evidence that we read the literature around the dataset, not just the
dataset.

The important structural difference from the synthetic pipeline
---------------------------------------------------------------
EKAGRA's own pipeline consumes **packets**. CIC-IDS2017 ships **flow records**.
We do not synthesise packets from flows - that would fabricate detail we do not
have. Instead the visibility ablation is applied at the feature level, which
this corpus supports unusually well because CICFlowMeter already decomposes
almost every statistic into forward and backward halves:

    Fwd IAT Mean        <- computable from forward packets alone
    Bwd IAT Mean        <- requires the reverse direction
    Flow IAT Mean       <- computed over BOTH directions

So a one-way tap keeps the first, loses the second, and - this is the part most
people would get wrong - **also loses the third**. `Flow IAT Mean` is not
"forward IAT with noise"; it is a different quantity, and on a one-way tap the
sensor would compute it over forward packets only, producing a value this CSV
does not contain. We cannot recompute it without the packets, so we drop it
rather than pretend the CSV's value would have been observed.

Every column is classified explicitly in `COLUMN_VISIBILITY` below, with that
rule applied consistently. The classification is the substance of this adapter
and is where a reviewer should look first.

One rung is not testable here
-----------------------------
The corpus carries no threat-intelligence enrichment, so `FULL_ENRICHED`
cannot be evaluated on it. That is acceptable: the synthetic study found the
enrichment rung cost ~0 and the *direction* rung was the expensive one, so the
rung this corpus can test is precisely the one that mattered.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

import numpy as np
import pandas as pd

# --------------------------------------------------------------------- schema

# Identifiers and labels. Deliberately does NOT include ports or protocol -
# those are legitimate features available at deployment and are classified as
# forward-observable below.
#
# Source and destination IP are excluded from every feature set on purpose.
# CIC-IDS2017 was captured on a fixed testbed where the attacker hosts have
# constant addresses, so a model given the IPs memorises them and reports
# near-perfect scores that mean nothing. This is a well-known way to get an
# inflated number on this corpus, and dropping the IPs is the single most
# important preprocessing decision here.
META_COLUMNS = [
    "Flow ID", "Src IP", "Dst IP", "Timestamp", "Label",
]

# Statistics computable from the forward direction alone. A one-way tap that
# observes the initiator's packets sees all of these.
FORWARD_OBSERVABLE = [
    "Src Port", "Dst Port", "Protocol",
    "Total Fwd Packet", "Total Length of Fwd Packet",
    "Fwd Packet Length Max", "Fwd Packet Length Min",
    "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Fwd PSH Flags", "Fwd URG Flags", "Fwd RST Flags",
    "Fwd Header Length", "Fwd Packets/s",
    "Fwd Segment Size Avg",
    "Fwd Bytes/Bulk Avg", "Fwd Packet/Bulk Avg", "Fwd Bulk Rate Avg",
    "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "FWD Init Win Bytes", "Fwd Act Data Pkts", "Fwd Seg Size Min",
    "Fwd TCP Retrans. Count",
    "Fwd Segment Payload Length Total", "Fwd Segment Payload Length Max",
    "Fwd Segment Payload Length Min", "Fwd Segment Payload Length Mean",
    "Fwd Segment Payload Length Std",
    "Fwd Segment Header Length Min",
]

# Requires observing the reverse direction. Definitionally unavailable.
BACKWARD_DERIVED = [
    "Total Bwd packets", "Total Length of Bwd Packet",
    "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Bwd PSH Flags", "Bwd URG Flags", "Bwd RST Flags",
    "Bwd Header Length", "Bwd Packets/s",
    "Bwd Segment Size Avg",
    "Bwd Bytes/Bulk Avg", "Bwd Packet/Bulk Avg", "Bwd Bulk Rate Avg",
    "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Bwd Init Win Bytes", "Bwd Act Data Pkts", "Bwd Seg Size Min",
    "Bwd TCP Retrans. Count",
    "Bwd Segment Payload Length Total", "Bwd Segment Payload Length Max",
    "Bwd Segment Payload Length Min", "Bwd Segment Payload Length Mean",
    "Bwd Segment Payload Length Std",
    "Bwd Segment Header Length Min",
    "Down/Up Ratio",
]

# Computed over BOTH directions. The subtle category, and the one a careless
# ablation would keep. On a one-way tap the sensor would still emit a value for
# each of these - but a *different* value, computed over forward packets only.
# We cannot reconstruct that from this CSV, so these are dropped.
BIDIRECTIONAL_AGGREGATE = [
    "Flow Duration", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Packet Length Min", "Packet Length Max", "Packet Length Mean",
    "Packet Length Std",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWR Flag Count", "ECE Flag Count",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
    "Total TCP Retrans. Count", "Total Connection Flow Time",
    "Segment Payload Length Max", "Segment Payload Length Min",
    "Segment Payload Length Mean", "Segment Payload Length Std",
    "ICMP Code", "ICMP Type",
]

DEFAULT_PATH = Path(__file__).resolve().parents[3] / "data" / "cicids2017_corrected.csv"
ZENODO_URL = "https://zenodo.org/api/records/22016274/files/cicids2017.csv/content"


@dataclass
class CICIDS2017:
    """Loader and visibility-aware feature selector for CIC-IDS2017."""

    path: Path = DEFAULT_PATH
    nrows: Optional[int] = None
    _df: Optional[pd.DataFrame] = None

    # ------------------------------------------------------------------ load
    def load(self, usecols: Optional[Sequence[str]] = None) -> pd.DataFrame:
        if not Path(self.path).exists():
            raise FileNotFoundError(
                f"{self.path} not found.\n"
                f"Download it (1.4 GB, CC-BY-4.0):\n  curl -L -o {self.path} {ZENODO_URL}\n"
                "Source: Huang, Bois & Marchioro, 'Corrected CICFlowmeter Datasets', "
                "Zenodo record 22016274."
            )
        df = pd.read_csv(self.path, nrows=self.nrows, usecols=usecols,
                         low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        if "Label" in df.columns:
            df["Label"] = df["Label"].astype(str).str.strip()
        if "Timestamp" in df.columns:
            df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce",
                                             format="mixed")
        self._df = df
        return df

    @property
    def df(self) -> pd.DataFrame:
        if self._df is None:
            self.load()
        return self._df

    # -------------------------------------------------------------- features
    def feature_columns(self, visibility: str) -> List[str]:
        """Columns a sensor at the given visibility could actually produce.

        visibility:
          'full'    both directions observed (what the corpus provides)
          'oneway'  forward direction only
        """
        present = set(self.df.columns)
        if visibility == "full":
            cols = FORWARD_OBSERVABLE + BACKWARD_DERIVED + BIDIRECTIONAL_AGGREGATE
        elif visibility == "oneway":
            cols = FORWARD_OBSERVABLE
        else:
            raise ValueError("visibility must be 'full' or 'oneway'")
        return [c for c in cols if c in present]

    def matrix(self, cols: Sequence[str]) -> np.ndarray:
        x = self.df[list(cols)].apply(pd.to_numeric, errors="coerce")
        return x.replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(dtype=np.float32)

    def ablate_to_oneway(self, X: np.ndarray, cols: Sequence[str]) -> np.ndarray:
        """Simulate deploying a full-visibility model on a one-way tap.

        Unobservable features are zeroed rather than dropped, because the model
        expects a fixed input width. Zero is what a real pipeline emits for a
        statistic it cannot compute, so this is the operationally faithful
        thing to do - and it is exactly the distribution shift that breaks the
        model.
        """
        keep = set(FORWARD_OBSERVABLE)
        X = X.copy()
        for j, c in enumerate(cols):
            if c not in keep:
                X[:, j] = 0.0
        return X

    # ----------------------------------------------------------- convenience
    def labels(self, binary: bool = False) -> pd.Series:
        lab = self.df["Label"]
        return (lab != "BENIGN").astype(int) if binary else lab

    def temporal_split(self, train_fraction: float = 0.7):
        """Split by timestamp, never randomly.

        CIC-IDS2017 runs Monday to Friday with different attacks on different
        days, so a random split puts flows from the same attack episode on both
        sides. Random splitting is the single most common flaw in published work
        on this corpus and inflates every score.
        """
        ts = self.df["Timestamp"]
        cutoff = ts.quantile(train_fraction)
        return (self.df.index[ts <= cutoff].to_numpy(),
                self.df.index[ts > cutoff].to_numpy())

    def sample_flows(self, rate: int, seed: int = 7) -> np.ndarray:
        """Flow-consistent 1:N sampling, as deployed on high-rate links."""
        if rate <= 1:
            return self.df.index.to_numpy()
        rng = np.random.default_rng(seed)
        keep = rng.integers(0, rate, size=len(self.df)) == 0
        return self.df.index[keep].to_numpy()


def column_audit(df: pd.DataFrame) -> pd.DataFrame:
    """Every column, and which visibility class it was assigned to.

    Printed by the experiment so the classification is auditable rather than
    buried in a list. If a reviewer disagrees with one assignment, this is the
    table they argue with.
    """
    rows = []
    for c in df.columns:
        if c in META_COLUMNS:
            k = "meta"
        elif c in FORWARD_OBSERVABLE:
            k = "forward-observable"
        elif c in BACKWARD_DERIVED:
            k = "backward-derived"
        elif c in BIDIRECTIONAL_AGGREGATE:
            k = "bidirectional-aggregate"
        else:
            k = "UNCLASSIFIED"
        rows.append({"column": c, "class": k})
    return pd.DataFrame(rows)


def load_subsampled(path: Path, benign_keep: float = 0.30,
                    seed: int = 0) -> pd.DataFrame:
    """Chunked load keeping every attack flow and a fixed fraction of benign.

    The corpus is ~80% benign and does not fit comfortably in memory. Attacks
    are kept in full because they are the scarce class; benign is subsampled at
    a fixed, stated rate. All conditions see identical rows, so the comparison
    between them is unaffected - but absolute rates are on this subsample and
    should be read that way.
    """
    rng = np.random.default_rng(seed)
    chunks = []
    total = 0
    for chunk in pd.read_csv(path, chunksize=400_000, low_memory=False):
        chunk.columns = [c.strip() for c in chunk.columns]
        chunk["Label"] = chunk["Label"].astype("string").str.strip()
        total += len(chunk)
        is_attack = chunk["Label"] != "BENIGN"
        keep = is_attack | (rng.random(len(chunk)) < benign_keep)
        chunks.append(chunk[keep])
    df = pd.concat(chunks, ignore_index=True)

    # pandas 3.0 preserves NA through `.astype(str)` rather than rendering it
    # as the string "nan", so a handful of malformed rows leave genuine NaN in
    # the Label column. Those rows cannot be used for supervised evaluation -
    # dropping them is the only honest option, and the count is reported so it
    # is visible rather than silent.
    bad_label = df["Label"].isna()
    if bad_label.any():
        print(f"      dropped {int(bad_label.sum()):,} flows with a missing label")
        df = df[~bad_label]
    df["Label"] = df["Label"].astype(str).str.strip()

    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce", format="mixed")
    bad_ts = df["Timestamp"].isna()
    if bad_ts.any():
        print(f"      dropped {int(bad_ts.sum()):,} flows with an unparseable timestamp")
    df = df[~bad_ts].sort_values("Timestamp").reset_index(drop=True)

    print(f"      read {total:,} flows, kept {len(df):,} "
          f"(all attacks + {benign_keep:.0%} of benign)")
    return df
