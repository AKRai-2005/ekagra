# EKAGRA

**Threat detection that survives a one-way tap.**

Smart India Hackathon 2026 · Problem Statement **SIH26145** · National
Technical Research Organisation (NTRO) · Theme: Blockchain & Cybersecurity ·
Team **AlgoRhythms**

> *AI-Based Detection of Cyber Threats in Unidirectional IP Traffic*

Companion project: **[KALACHAKRA](https://github.com/AKRai-2005/kalachakra)**
(SIH26153) — *where is this going, and what if I act?* Roughly 60–70% of its
data foundation is shared with this repository.

---

## The problem

A monitoring enclave behind a **data diode** sees traffic crossing the link and
has **no path back**: it cannot query a threat-intelligence service, probe a
host, or block anything. Every widely-used NIDS dataset ships *bidirectional*
flow records, and most published pipelines assume they can enrich observations
with an outbound call. Deploy a conventionally-trained detector there and it
collapses.

We measured how far it collapses, and then found out why.

## The result

On the corrected CIC-IDS2017 re-extraction — **877,801 flows**, temporal split,
source and destination IP excluded from every feature set:

| Condition | Features | Binary F1 |
|---|---|---|
| A — full visibility | 103 | 0.9793 |
| C — deployed on a one-way tap | 35 forward-observable | **0.6903** |
| E — purpose-built sensor | 35 + 16 host-window | **0.9810** |
| G — host-window aggregates **alone** *(our control)* | **16** | **0.9812** |

> **The loss is not the missing direction. It is the missing per-host state.**
> A sensor that keeps fan-out, source-IP entropy, peer concentration and
> arrival periodicity across a 60-second window loses essentially nothing from
> being on a one-way tap. A per-flow extractor on the same tap loses 0.29 F1.

**Our own control (row G) narrowed our headline claim, and we published it
rather than dropping it.** It was then stress-tested: at low attack density,
where attack flows share a host-window cell with benign traffic at 59:1 to
188:1, host-window-alone collapses from 0.599 to 0.28 macro-F1 while full
visibility holds 0.77–0.86. So the actionable rule is: **keep per-host state,
but never run on it alone.** That is what the shipped sensor does.

*Source: `backend/results/exp04_verdicts.json`, `exp10_verdicts.json`.*

## What is built

```
packets -> visibility filter -> flow assembler -> streaming host-window
        -> detector heads -> conformal calibration -> evidence bundle
        -> read-only API + console
```

| Property | Measured |
|---|---|
| Flow-level throughput | 171,501 flows/s |
| Packet pipeline, 1 shard / 12 shards | 35,992 / 108,938 packets/s (3.03x) |
| Line rate for 1 Gbps at 700 B | 178,571 packets/s — **not reached** |
| Sensor state | **2.66 MB** for 14,817 hosts |
| End-to-end latency | **75 s** (60 s window + 15 s lateness budget) |
| Streaming vs exact batch | 0.98120 vs 0.98119 binary F1; 14 of 16 features bitwise identical |
| Conformal calibration | coverage 0.908, abstention 9.11%, accuracy on answered 99.55%, ECE 0.00084 |
| Tests | **288 passing** |

> **On throughput, our own documents disagree.** `exp07_verdicts.json` records a
> best case of 108,938 pkt/s (~610 Mbps); an earlier run recorded in
> `RESULTS.md` gives 119,918 pkt/s (~672 Mbps). Throughput benchmarks vary with
> machine load. The honest statement is **610–672 Mbps, and 1 Gbps is not
> reached.** We previously claimed 1 Gbps and retracted it.

## Three things only real captured traffic could tell us

- **94% of real TLS ClientHellos span TCP segments** — 91 of 97 failed before a
  reassembler was built.
- **JA3 gave 92 distinct fingerprints where JA4 gave 7** over the same 97
  hellos, because Chrome randomises extension order. JA3 is unusable as a
  rarity signal on modern browsers.
- **UDP/443 beat TCP/443 by 80,291 to 32,069 packets.** Most HTTPS is QUIC. We
  called QUIC a hard ceiling; we were wrong, and now decrypt QUIC Initials
  (RFC 9001) to reach the ClientHello. That is not payload decryption — 1-RTT
  keys stay out of reach.

## Design constraints, enforced rather than asserted

| Constraint | Enforcement |
|---|---|
| No outbound connections in the detection path | **A CI test fails the build** if any component opens a socket (`tests/test_readonly_constraint.py`) |
| Read-only API | A test fails the build if a write endpoint appears |
| No payload decryption | Payload bytes never reach feature code |
| Console runs air-gapped | No framework, no CDN, no build step — one HTML file |

## Quickstart

```bash
cd backend
pip install -e .

python -m pytest tests/ -q                   # 288 tests
python experiments/exp04_forward_features.py # the headline ablation
python demo.py                               # read-only API + console on :8000
python analyse_pcap.py <capture.pcapng>      # run the packet path on a capture
```

The console also works with **no server at all** — open `frontend/index.html`
directly and it falls back to the bundled snapshot.

### Datasets are not in this repository

They are third-party, large, and not ours to redistribute.

- **CIC-IDS2017 (corrected re-extraction)** — Zenodo record `22016274`,
  CC-BY-4.0. Chosen over the original CSVs, which have documented label and
  feature-extractor defects. Place under `backend/data/`.

## How to read the evidence

Every experiment carries **pre-registered predictions** written into the file
before the first run. The run prints a verdict for each and persists it to
`backend/results/exp*_verdicts.json`. Predictions are never edited afterwards.

**42 predictions. 17 refuted — including our headline claim.**

A result that only ever confirms its authors is the one to distrust.

| Document | What it is |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Design rationale and the research argument |
| [`RESULTS.md`](RESULTS.md) | Full experiment log, including every refutation |
| [`submission/REPORT_EKAGRA_SIH26145.pdf`](submission/) | 43-page complete technical, functional and presentation reference |
| [`submission/JUDGE_QA.md`](submission/JUDGE_QA.md) | Anticipated questions with honest answers |

## Known limitations

- **1 Gbps is not reached** (610–672 Mbps measured).
- **DGA is the weak class.** Dictionary-based families are close to unusable:
  suppobox 0.6949 and banjori 0.7475 combined AUC, against uniform-random
  0.9787. A threshold calibrated on generated benign names flags **89.6% of
  real benign names** — the strongest evidence our generated corpus is a
  controlled instrument, not a substitute for data.
- **Packet-size and timing sequences are not implemented**, and the problem
  statement names them beside fingerprints. This is our clearest remaining gap.
- **No authentication or authorisation.** A recorded scope decision: the
  security model assumes placement inside an already-restricted enclave.
- **Tamper-*evident*, not tamper-proof.** The SHA-256 evidence chain detects
  edits; an attacker with write access could rewrite it consistently.
- Sharding is not bit-exact (8–21 cells per configuration disagree).

## Licence and attribution

Built for Smart India Hackathon 2026 by Team AlgoRhythms.
CIC-IDS2017 is used under CC-BY-4.0 from its original authors.
