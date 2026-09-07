# EKAGRA — Architecture

**SIH 2026 · PS SIH26145 · NTRO**
*AI-Based Detection of Cyber Threats in Unidirectional IP Traffic*

---

## 1. The constraint that defines the system

NTRO's problem statement describes a **data diode / passive mirror** deployment:

> "The enclave can see everything crossing the link, but it has no physical or protocol-level path back into the production network."

Three architectural constraints follow, quoted from the PS:

| Constraint | PS wording | How we enforce it |
|---|---|---|
| Read-only ingest | "Any design that assumes a return path, a live query to the source, or an inline block is out of scope." | No outbound sockets in the detection path. Enforced by a **CI test that fails the build** if one is opened. |
| No payload decryption | "TLS/QUIC sessions must be analysed from metadata only." | Detectors consume only handshake metadata, packet sizes and timings. Payload bytes are never read into feature code. |
| Streaming, not batch | "must process traffic incrementally and raise alerts with bounded latency" | Single-pass packet iterator, O(1)-memory sketches, windowed emit. No global sort, no full-dataset pass. |

These are not documentation claims. Each has a test in `tests/`.

---

## 2. The central research idea: visibility-matched training

> **Status: this section was rewritten on 30 Aug 2026 after the experiment refuted the original hypothesis.** The first version claimed a novel "unidirectional-native" feature set beats the published baseline. It does not. What follows is what the data actually supports. The refuted version and its verdicts are preserved in `experiments/exp01_ablation.py` — deliberately, because the correction is part of the evidence that these numbers are real.

Every widely-used NIDS dataset (CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15) ships **bidirectional** flow records, and most published pipelines assume they can enrich observations by calling out to reputation or WHOIS services. A diode enclave may have neither.

### The finding

> **Rewritten twice as evidence arrived.** Generated traffic said one thing, the
> real corpus said another, and controls on the real corpus said a third. The
> current statement is below; the full trail is in [`RESULTS.md`](RESULTS.md).

> **On CIC-IDS2017, windowed host state dominates the detection task. Once a
> sensor maintains it — fan-out, source-IP entropy, peer concentration, arrival
> periodicity, volume against a per-host baseline — losing the reverse traffic
> direction costs essentially nothing (0.981 one-way vs 0.979 full visibility).
> Without that host state, the same loss costs 0.29 binary-F1 (0.690 vs 0.979).**

The practical recommendation for a diode deployment follows directly and is
worth more than the original claim: **the thing that matters is not which
direction you can see, it is whether your sensor keeps per-host state across a
window.** A per-flow feature extractor pointed at a one-way tap will look
catastrophically bad; the same tap with windowed host state will not.

That caveat has now been tested, and half of it did not survive.

Experiment 10 re-times and re-homes the same real flows so that attacks are
low-rate and, crucially, share their (host, window) cells with benign traffic —
a compromised insider rather than a dedicated external attacker. Per-flow
features are untouched; only *when* and *from which host* an attack appears
changes. Under those conditions:

- **The one-way tap still costs nothing.** Forward-only flow features track or
  beat full visibility at every density (0.937–0.994 vs 0.937–0.983 binary-F1).
  The claim this project is named for holds.
- **"Host-window aggregates alone are enough" does not hold.** In exp04 those 16
  features were the *best* condition at 0.599 macro-F1, beating all 103
  full-visibility features. Here they are the *worst* by a wide margin: 0.35
  falling to 0.28, while full visibility holds 0.77–0.86.

The mechanism is structural, not statistical. Host-window features are computed
per cell, so every flow in a cell receives the same vector. When attack flows
are outnumbered 59-to-1 to 188-to-1 inside their own cell, no model can separate
them from their neighbours on those features. exp04's result was real, but it
was measuring cells that were 98% attack.

So the recommendation above narrows to: **keep per-host state, but do not run on
it alone.** Windowed host state is what makes a one-way tap viable; per-flow
evidence is what still finds the quiet intrusions. The sensor needs both, which
is what condition E ships.

### Two secondary findings worth a sentence each

1. **Removing the reputation feed *improved* results** (0.926 → 0.971). At 55% recall and 3% false-positive rate, a commercial-grade IP-reputation feed is net negative once behavioural features are present. The diode constraint costs nothing here — it is a feature.
2. **Flow sampling at 1:16 barely hurts** once training is visibility-matched (0.939). The expensive loss is direction, not volume.

### The honest limits

- The synthetic study is a controlled instrument, not evidence on its own. `ingest/replay.py` + `experiments/exp03_cicids_ablation.py` run the same hypothesis on **real captured traffic** (corrected CIC-IDS2017, Zenodo 22016274) — see §9.
- DGA is the weak class throughout (F1 0.60–0.71) and is over-predicted (precision ~0.49 at full recall). Stated rather than hidden.
- `ddos` has only 45 test rows. That number is thin and the F1 of 1.000 should be read with that in mind.

---

## 3. Data flow

```
  ┌─────────────┐
  │  Source     │  PCAP replay │ CSV replay │ synthetic generator
  └──────┬──────┘  (all implement the same read-only iterator)
         │  Packet stream (ts, 5-tuple, size, flags, ttl, dns_qname, tls_fp)
         ▼
  ┌─────────────┐
  │ DiodeFilter │  ◀── the ablation transform. Drops one direction.
  └──────┬──────┘      Configurable: egress-tap / ingress-tap / off
         │  Observed packets only
         ▼
  ┌─────────────────────────────────────────┐
  │ Feature layer (streaming, O(1) memory)  │
  │  · FlowTable      per-flow forward state│
  │  · Sketches       CMS / HLL / decayed   │
  │  · DNS stats      qname entropy, n-gram │
  │  · TLS stats      JA4-like fp rarity    │
  │  · Size/IAT seq   ring buffers          │
  └──────┬──────────────────────────────────┘
         │  WindowFeatures every W seconds
         ▼
  ┌─────────────────────────────────────────┐
  │ Detector heads (parallel, independent)  │
  │  volumetric · beacon · dga · scan       │
  │  · exfil · encrypted                    │
  └──────┬──────────────────────────────────┘
         │  raw scores
         ▼
  ┌─────────────┐
  │ Calibration │  conformal → calibrated confidence + ABSTAIN
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │  Evidence   │  hash-chained bundle: packet indices, feature
  │   signer    │  vector, model hash, decision path
  └──────┬──────┘
         ▼
   alert bus → SSE → React console
```

**The one-way arrow is real.** No component to the right of `Source` can call anything to its left. The package layout mirrors this: `detect/` may import from `features/`, never the reverse; nothing imports `ingest.source` except the pipeline entry point.

---

## 4. Threat classes and the signal each depends on

The PS names six. This table is the design rationale — which reverse-channel signal is lost, and what forward-side statistic replaces it.

| Class | Classic bidirectional signal | Lost under diode? | Unidirectional-native replacement |
|---|---|---|---|
| Volumetric / protocol DDoS | SYN with no returning SYN-ACK | **Yes** — completion is unobservable | Source-IP entropy (HLL + CMS), SYN rate per dst, spoofed-source dispersion |
| C2 beaconing | Request/response round-trip regularity | Partly | Inter-arrival periodicity + jitter on forward packets only; destination concentration |
| DGA / DNS tunnelling | NXDOMAIN response rate | **Yes** — responses unobserved | Query-name character entropy, n-gram improbability, label length, qtype mix |
| Malware in encrypted sessions | Server certificate, JA3S | **Yes** — server side unobserved | Client JA4-like fingerprint rarity, packet-size sequence, IAT sequence |
| Reconnaissance / scanning | RST responses from closed ports | **Yes** | Fan-out cardinality per source (HLL over dst ports/hosts), burst structure |
| Data exfiltration | Outbound:inbound byte ratio | **Yes** — one side of ratio missing | Absolute outbound volume vs per-host decayed baseline, upload burst shape |

Five of six lose their primary signal. That is *why* condition B collapses, and it is the substance of the contribution.

---

## 5. Component design

### 5.1 `ingest/`
- `records.py` — `Packet`, `FlowKey`, immutable, `slots=True` for throughput.
- `synthetic.py` — labelled traffic generator. Benign classes include **periodic keepalives and telemetry**, deliberately, so beacon detection is not trivial. Attack classes per PS §a–f.
- `diode.py` — `DiodeFilter`. The ablation transform. Also the deployment component: in production this is the tap model.
- `replay.py` — PCAP / CSV adapters for CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15.

### 5.2 `features/`
- `sketches.py` — Count-Min Sketch, HyperLogLog, exponentially-decayed counters. Chosen because entropy and cardinality at line rate cannot use dictionaries.
- `flow_state.py` — per-flow forward-only state machine with LRU eviction.
- `extractors.py` — two feature sets, deliberately separate classes:
  - `BidirectionalFeatures` — reproduces the published feature convention.
  - `UnidirectionalFeatures` — our design.

### 5.3 `detect/`
One head per threat class. Gradient-boosted trees for tabular classes (they win on this data and are interpretable); a small sequence model for encrypted-session and beaconing. Each head exposes `score()` and `explain()`.

### 5.4 `calibrate/`
Split-conformal prediction over a held-out calibration set. Produces a calibrated confidence and an **abstention** decision: `INSUFFICIENT_EVIDENCE_UNDER_UNIDIRECTIONAL_CONSTRAINT`. Abstention is a first-class output, not a failure.

### 5.5 `evidence/`
Every alert carries a bundle: observed packet indices, the feature vector, model hash, decision path, and a hash chain linking it to the previous alert. Tamper-evident, replayable, and the answer to "prove this alert."

---

## 6. Metrics we report

Accuracy is deliberately **not** a headline number — these classes are heavily imbalanced and accuracy hides that.

- Per-class **precision / recall / F1**
- **Precision@k** — what an analyst sees at the top of the queue
- **Alerts per hour at fixed recall** — the operational number
- **Expected Calibration Error** — is the confidence meaningful
- **Abstention rate** vs accuracy-on-answered
- **p99 detection latency** and sustained **packets/sec**

---

## 7. What we are deliberately not building

| Not building | Why |
|---|---|
| Our own packet parser | Solved problem. Use `dpkt`/`scapy` at the adapter boundary only. |
| Login / RBAC / multi-tenancy | Zero evaluation credit, days of work. |
| A mobile app | Not in the PS. |
| Any LLM in the detection path | Latency, non-determinism, and it would break the evidence guarantee. |
| All six detectors at mediocre quality | Three done properly beats six at 60%. Priority: volumetric → dga → beacon. |
| An inline blocking mode | Explicitly out of scope per the PS. |

---

## 9. Real-corpus validation

The synthetic pipeline consumes packets; CIC-IDS2017 ships flow records. We do
**not** synthesise packets from flows — that would fabricate detail we do not
have. Instead the ablation is applied at the feature level, which this corpus
supports unusually well because CICFlowMeter already decomposes nearly every
statistic into forward and backward halves.

Each of the 103 features is classified explicitly in `ingest/replay.py`:

| class | n | under a one-way tap |
|---|---|---|
| forward-observable | 35 | **kept** — computable from forward packets alone |
| backward-derived | 33 | dropped — definitionally needs the reverse direction |
| bidirectional-aggregate | 35 | dropped — see below |

The third row is the one a careless ablation gets wrong. `Flow IAT Mean` is not
"forward IAT with noise"; on a one-way tap the sensor computes a *different
quantity* over forward packets only, which this CSV does not contain. We cannot
reconstruct it without the packets, so it is dropped rather than assumed
observed. `column_audit()` prints the full classification so a reviewer can
argue with any single assignment, and `tests/test_cicids_adapter.py` pins the
invariants.

Two preprocessing decisions worth stating:

- **Source and destination IP are excluded from every feature set.** The
  testbed uses fixed attacker addresses; a model given the IPs memorises them
  and reports a meaningless near-perfect score. This is the most important
  preprocessing decision in the file.
- **Temporal split, never random.** CIC-IDS2017 runs Monday–Friday with
  different attacks on different days; a random split puts flows from the same
  attack episode on both sides. Some attack classes therefore appear only in
  test — that is realistic (novel attack types) and is reported, and it is why
  **binary F1 is the headline metric** with macro-F1 alongside.

The `FULL_ENRICHED` rung is not testable on this corpus — it carries no
threat-intelligence features. Acceptable: the synthetic study found the
enrichment rung cost ~0 and the *direction* rung was expensive, so this corpus
tests exactly the rung that mattered.

---

## 8. Build order

1. `ingest` + `diode` + synthetic generator — *makes everything runnable with no downloads*
2. `features` both sets
3. `experiments/exp01_ablation.py` — **the chart. This is the highest-value artifact in the repo.**
4. Detector heads, calibration
5. Streaming pipeline + throughput benchmark
6. Evidence bundles
7. Console
8. ~~Real-dataset adapters~~ — done (CIC-IDS2017)
