# EKAGRA — results log

## Experiment 11 — the DGA head against REAL benign names

Every DGA number before this was a closed loop: our generator makes benign names
from a short fixed list and DGA names by uniform character sampling, so the
entropy gap is enormous by construction. Experiment 11 breaks the loop on both
sides — benign names come from a **real 812 MB, 14-minute capture** (6,450
queries, 491 distinct names, **279 distinct registrable domains**), and the
malicious names come from reimplementations of *published DGA families*, not
from our generator.

Benign names are scored **leave-one-out**: each is scored by a bigram model
fitted on the other 278. No name from the capture is stored, printed or
committed.

| family | shape | entropy | length | bigram | best |
|---|---|---|---|---|---|
| uniform | random a-z0-9 (**what we generate**) | 0.9787 | 0.9614 | 0.9681 | **0.9787** |
| necurs | random a-z, 7-21 | 0.8419 | 0.8438 | **0.9434** | 0.9434 |
| conficker | random a-z, 8-11 | 0.6827 | 0.6964 | **0.9402** | 0.9402 |
| matsnu | verb-noun dictionary | 0.8209 | 0.8941 | 0.5436 | 0.8941 |
| banjori | mutates 4 chars of a **real** domain | 0.5843 | 0.5601 | **0.7475** | 0.7475 |
| suppobox | two dictionary words | 0.6654 | 0.6949 | 0.5183 | 0.6949 |

### The causal bigram model earns its keep — but only with history

Prediction D5 was written as a deletion test: *"if the causal model never wins,
it is 1,400 integers of state earning nothing and should be deleted."* On a
first, smaller capture (54 distinct names) it looked marginal. On 279 it is the
**strongest feature on four of six families**, and on conficker it beats raw
entropy 0.940 to 0.683.

The reason is measurable. Fitting the model on the first *n* benign names and
scoring only names it has never seen:

| benign names seen | held out | uniform | conficker | necurs | banjori |
|---|---|---|---|---|---|
| 10 | 269 | 0.560 | 0.571 | 0.559 | 0.482 |
| 25 | 254 | 0.755 | 0.733 | 0.730 | 0.580 |
| 50 | 229 | 0.782 | 0.747 | 0.748 | 0.561 |
| 100 | 179 | 0.946 | 0.894 | 0.900 | 0.623 |
| **200** | 79 | **0.976** | **0.947** | **0.953** | **0.715** |
| 239 | 40 | 0.959 | 0.921 | 0.924 | 0.680 |

**Below about 50 distinct benign names the feature is near chance; by 200 it is
strong.** The final row is not a regression — its held-out set is the smallest
and therefore the noisiest estimate. Read the trend, not the tail.

This is the operationally useful form of the result: the DGA head has a
**warm-up period**, and switching it on cold produces noise.

*(An earlier version of this table fitted and scored on the same names at the
largest size and reported 0.999. That was a leak, caught and fixed; every size
now leaves at least 40 unseen names.)*

### Four results worth stating plainly

**Our own DGA family remains the easiest one.** 0.9787 against uniform sampling,
exactly what `_dga_name()` produces. Every earlier DGA number was measured on
the easiest case that exists.

**Banjori is the hardest, as predicted (D3 holds).** 0.7475 — and *only* the
bigram model gets there; entropy sits at 0.584, barely above chance. It keeps a
real domain's tail and rewrites four characters.

**Dictionary families beat prediction D2, which failed.** We expected AUC < 0.75
and matsnu reached 0.894 — but read the columns: that is **length**, not
character statistics, and the bigram model is at 0.544, near chance. Suppobox at
0.695 is the better guide to what dictionary DGAs actually cost us.

**The operating point is where this gets uncomfortable.**

| threshold | uniform | necurs | matsnu | conficker | banjori |
|---|---|---|---|---|---|
| 1% FPR | 0.662 | 0.240 | 0.037 | 0.000 | 0.029 |
| 5% FPR | 0.866 | 0.464 | 0.210 | 0.018 | 0.067 |
| 10% FPR | 0.958 | 0.612 | 0.461 | 0.127 | 0.146 |

D4 fails: catching 90% of even the *easiest* family costs more than 5% false
positives on benign DNS — 5,000 false alerts an hour on a 100,000-query network.
This is why the conformal abstention layer exists rather than a bare threshold.

### The prediction that failed hardest — and the most useful thing here

**D6: a threshold calibrated on our generated benign names flags 89.6% of real
benign names.** Not 5%, as predicted.

Our synthetic benign traffic is nothing like real traffic. **Any threshold tuned
on the generator is meaningless on a real network**, and this is the strongest
evidence in the project for why the generated corpus is a controlled instrument
rather than a substitute for data. It also retroactively justifies the conformal
layer: calibrate on the traffic you will actually see.

Reproduce with your own capture:

    python experiments/exp11_dga_real_benign.py --capture yours.pcapng

## Severity — closing the second half of the PS's alert contract

SIH26145 asks alerts to carry **severity and confidence**. We shipped confidence
only until now. `detect/severity.py` adds the impact axis, and two decisions in
it are worth defending out loud.

**It is not `class x confidence`.** That is the obvious formula and it destroys
both inputs: a 0.99-confidence port scan and a 0.55-confidence exfiltration
multiply to roughly the same number and demand opposite responses. CVSS keeps
base score apart from confidence, NIST SP 800-30 keeps impact apart from
likelihood, and so does this. `severity()` does not accept a confidence
argument, and a test asserts its signature so nobody can quietly add one.

**The first version of it was wrong, and the corpus said so.** Every class was
given its own magnitude feature — ports for scanning, flows for beaconing.
Measured over 90,794 logged alerts, the medians came out at **0.00**:

| class | chosen feature | median over its own alerts |
|---|---|---|
| scan | `hw_src_n_dports` | 0.00 |
| beacon | `hw_src_n_flows` | 0.00 |

An alert fires on a **host**, and the evidence can sit on either side of that
host's cell. A scan alert fires on the host *being scanned*, whose `hw_src_*`
counters are empty by construction. Half the magnitude features were reading the
wrong side, returning a silent zero, and filing established C2 beacons as
"low".

The fix was to narrow the claim rather than find a cleverer feature. Volume is
used as magnitude **only where volume is impact**, read side-agnostically:

| class | median `max(src,dst)` bytes | volume is impact? |
|---|---|---|
| exfil | 2,258,390 | yes — it is the damage |
| encrypted | 1,922 | yes — covert-channel throughput |
| dga | 15,910 | no |
| beacon | 444 | no — a stealthy beacon is not a milder one |
| scan | 296 | no |
| ddos | 74 | no — per-cell volume says nothing |

Every other class takes its kill-chain weight unmodified. **A magnitude that
reads the wrong side is worse than no magnitude, because it looks
quantitative.**

Two smaller things the tests caught while building it: *present-but-zero* and
*absent* were being conflated (measuring zero bytes should lower an
exfiltration to its class floor; never measuring should not move it at all),
and severity is deliberately **not hashed** into the evidence chain — it is a
pure function of `threat_class` and `features`, both already committed, so
hashing it would add a field that can never disagree while invalidating every
log written before it existed.

---

Predictions are written into each experiment file **before** the first run and
are not edited afterwards. The verdicts below are printed by the runs
themselves.

---

## Protocol features — closing two problem-statement gaps

SIH26145 names six threat categories. Two are defined by protocol evidence the
sixteen host-window aggregates deliberately ignore:

> (c) DGA domains and DNS tunnelling — "entropy and **n-gram** analysis of DNS
> query names, including anomalies in query length"
> (d) Malware in encrypted sessions — "**JA3/JA3S or JA4 fingerprints**,
> packet-size and timing patterns", without decryption

Both heads shipped **knowingly handicapped**: the features they needed did not
exist in the path that fed them. `features/protocol.py` now supplies nine, as a
**separate group** rather than appended to the sixteen — CIC-IDS2017 carries no
query names or fingerprints, so folding them in would have changed the feature
vector every exp03/04/05 number was measured with and added nine permanently
zero columns on the real corpus.

### Measured on a real capture — and JA3 turned out not to work

A 147 MB, 6-minute capture of ordinary browsing (148,416 IP packets) was run
through the new path. Two findings, both of which only appear on real traffic:

**1. 94% of real ClientHellos span TCP segments.** The first version of
`pcap.py` did no reassembly, reasoning that a hello fits in one segment. Of 97
ClientHellos, **6 parsed and 91 did not** — every failure a record declaring
1.7–2.0 KB against a ~1460-byte segment, because a modern hello carries ALPN,
key shares, session tickets and padding. A JA3 feature at 6% coverage is not a
limitation, it is a broken feature that would have looked fine on generated
traffic indefinitely. A bounded, sequence-ordered ClientHello reassembler now
recovers **228 hellos with 3 abandoned**.

**2. JA3 is obsolete for modern browsers, and JA4 is not.** With reassembly
working, the fingerprints came out like this:

| | distinct values from 97 ClientHellos |
|---|---|
| JA3 | **92** |
| JA4 | **7** |
| distinct extension *sets* (order ignored) | **7** |

Chrome has randomised TLS extension **order** on every connection since v110
(2023), deliberately, to stop middleboxes ossifying the protocol. JA3 hashes
extensions in wire order, so it assigns nearly every connection its own
fingerprint — which would drive `hw_src_tls_fp_novel` to ~1.0 on entirely
benign traffic and make the encrypted-C2 head fire constantly. JA4 sorts the
cipher and extension lists, and collapses those 92 to 7 real client stacks:

    t13d1516h2_8daaf6152771_806a8c22fdea   54x   TLS 1.3, SNI, ALPN h2
    t13d1517h2_8daaf6152771_a87ad97598a9   26x
    t13d1516h1_8daaf6152771_3bf25d69fb96    8x   same ciphers, ALPN http/1.1
    t13d1714h1_5b57614c22b0_b6469b2faef8    6x   a different stack entirely
    t12d1809h2_4b22cbed5bed_7af1ed941c26    1x   a legacy TLS 1.2 client

The PS says "JA3/JA3S **or JA4**". On today's web that "or" is doing real work:
**the sensor defaults to JA4**, with JA3 selectable for lookups against
published corpora. Measured on the same capture, `hw_src_tls_fp_novel` has mean
**0.0039** — correctly near zero for benign traffic.

**3. Most HTTPS is HTTP/3 — and we reach it.** In the same capture UDP/443
outnumbered TCP/443 **80,291 to 32,069**. This log previously recorded that as a
hard ceiling on fingerprint coverage, on the reasoning that a QUIC ClientHello
sits inside an encrypted Initial packet. **That reasoning was wrong.** RFC 9001
derives Initial keys from the Destination Connection ID, which travels in the
clear, using a published salt — there is no secret, because the encryption
exists to stop middleboxes ossifying the handshake, not to hide it from an
observer.

`ingest/quic.py` implements the derivation (HKDF-Expand-Label, AES-128-ECB
header protection, AES-128-GCM AEAD) and reassembles the CRYPTO frames. On the
same capture:

| | hellos | distinct JA4 |
|---|---|---|
| over TCP | 228 reassembled | 7 |
| **over QUIC** | **72** | **4** |
| total | 300 | 11 |

**24% of handshakes were HTTP/3** and are invisible to a sensor that only reads
TLS-over-TCP. The QUIC fingerprints are self-validating: every one reads
`q13d03..h3` — QUIC, TLS 1.3, SNI present, exactly 3 cipher suites (Chrome's
QUIC set), ALPN `h3` — with an identical cipher hash across all of them, which
is what one client stack should produce. A key-derivation bug produces garbage,
not textbook values.

Correctness is pinned to **RFC 9001 Appendix A's own test vectors** rather than
to our own output, because crypto that "seems to work" is the most dangerous
code in this repository: a derivation bug yields plausible nonsense instead of
an exception, and nothing downstream would notice.

**This is not payload decryption**, which the problem statement forbids. The
1-RTT keys that protect application data come from the TLS handshake and are
unavailable to a passive observer. We decrypt exactly the one message that is
deliberately readable, and stop.

**The gap this used to leave, now closed.** Until this session there was no DNS
or TLS wire parser: `dns_qname` and `tls_fp` were consumed as already-extracted
fields that our own generator invented. `ingest/wire.py` now parses DNS messages
and computes **JA3/JA3S** to the published specification, and `ingest/pcap.py`
reads real pcap and pcapng files and feeds it. Verified end to end on a capture:
all nine protocol features non-zero, computed from packet bytes.

Two details that matter:

- **GREASE (RFC 8701) is stripped**, as the JA3 spec requires. Browsers inject
  random GREASE values per connection; leaving them in would give every Chrome
  connection a unique fingerprint and drive `hw_src_tls_fp_novel` to 1.0 on
  entirely benign traffic. Measured: six GREASE variants of one client collapse
  to a single fingerprint, while a different client stack gets a different one.
- **No TCP reassembly.** A ClientHello split across segments is not
  fingerprinted. On a one-way tap you cannot see the peer's acknowledgements, so
  a correct reassembler is a research problem of its own, and half of one would
  produce fingerprints that are subtly wrong rather than absent.

These parsers are the only code in EKAGRA reading adversary-controlled bytes, so
they are fuzzed: `test_wire.py` asserts no exception escapes on random input,
bit-flipped valid messages, and every truncation of both formats, and pins the
DNS compression-pointer loop that hangs a naive parser.

Both estimators are **score-then-learn**: a name is scored against the bigram
statistics of names seen before it, a fingerprint's rarity excludes its own
observation. Updating first would let a DGA burst normalise itself — a beacon
querying a thousand novel domains would make novel domains look common, and the
feature would go to zero exactly when it mattered.

### Separation on generated traffic

| feature | DGA cells | benign | ratio |
|---|---|---|---|
| `hw_src_qname_digit_ratio` | 0.183 | 0.001 | **201x** |
| `hw_src_dns_count` | 36.6 | 0.43 | 86x |
| `hw_src_qname_len_mean` | 40.2 | 0.97 | 42x |
| `hw_src_qname_entropy` | 4.14 | 0.25 | 17x |
| `hw_src_qname_bigram_rarity` | 4.89 | 0.36 | 13x |
| `hw_src_tls_fp_rarity` *(encrypted cells)* | 0.428 | 0.021 | **21x** |

### What it bought, measured by re-running exp09

| head | AP (full features) | AP (multiclass) | top feature now |
|---|---|---|---|
| **dga** | 0.898 → **0.981** | 0.906 → **1.000** | `hw_src_qname_bigram_rarity` |
| encrypted | 0.947 → **0.924** | 0.943 → **0.963** | `hw_src_tls_count` |

DGA is a decisive win — F1 also went 0.662 → **0.981**, and the top feature is
the n-gram statistic the problem statement asks for by name.

**Encrypted is mixed and should be read as such.** The head's own AP fell
0.023 while the multiclass model gained 0.020. Its top feature is
`hw_src_tls_count` — "does this host speak TLS at all" — rather than
fingerprint rarity, which is a weaker and more corpus-specific signal than we
were aiming for. `hw_src_tls_fp_novel` fires on only 5 cells in the generated
corpus, so the novelty channel is close to untested. The honest claim is that
the *evidence* is now present and the DGA case proves the plumbing works; the
encrypted case is not yet a win.

**Still missing for (d):** packet-size and timing sequences, which the PS lists
beside fingerprints. They do not survive flow-level aggregation, and the head
docstring says so rather than implying otherwise.

### A bug this exposed

Three experiments rebased a record's timestamp by rebuilding it positionally:

```python
FlowRecord(rec.ts - t0, rec.src, rec.dst, rec.dport, rec.fwd_pkts, rec.fwd_bytes)
```

which silently dropped every field added later — so the first exp09 re-run
showed *zero* protocol signal and the top features unchanged. Replaced with
`dataclasses.replace(rec, ts=rec.ts - t0)` in exp06, exp08 and exp09, which
survives future fields. Worth recording because the failure was invisible: the
run completed, the numbers looked plausible, and nothing errored.

## Experiment 07 — sharding does not reach line rate. Read this one first.

Experiment 06 measured 47,968 packets/s single-threaded, and the write-up said
the pipeline "shards cleanly by `hash(host)` with no cross-talk, so four workers
clear 1 Gbps". **That claim was wrong on both counts.** This experiment is what
happens when it gets built and measured.

### The architectural claim was wrong

`hash(host)` is **not a partition of the work**. A flow touches two hosts and
updates state for both, so its two updates belong on two different shards.
Sharding on `hash(src)` alone scatters every host's destination-role state
across every shard.

What is true is a two-stage decomposition, each stage partitioning on its own
key:

    packets --hash(src)--> assemble + source-role features --> flows
    flows   --hash(dst)--> destination-role features

`hash(src)` refines `hash(5-tuple)` on a one-way tap, so stages 1-2 fuse with no
shuffle. Only the destination stage repartitions. **Flows are consumed twice**,
so the cost model was never free linear speedup.

### The throughput claim was wrong

1 Gbps at this generator's ~700-byte average packet is **178,571 packets/s**.
That target is stated explicitly so the result cannot be graded against an
easier one.

| shards | wall | pkt/s | speedup | efficiency | 1 Gbps? |
|---|---|---|---|---|---|
| 1 | 11.5s | 44,396 | 1.00x | 1.00 | no |
| 2 | 8.2s | 62,436 | 1.41x | 0.70 | no |
| **4** | 5.7s | **89,976** | 2.03x | 0.51 | **no** |
| 6 | 4.6s | 110,646 | 2.49x | 0.42 | no |
| 8 | 4.8s | 107,435 | 2.42x | 0.30 | no |
| 12 | 4.3s | **119,918** | 2.70x | 0.23 | no |

**Best case 119,918 pkt/s — 672 Mbps.** Four workers reach 504 Mbps, not the
1 Gbps claimed. Scaling efficiency collapses from 0.70 at two shards to 0.23 at
twelve.

| Prediction | Verdict |
|---|---|
| W1 — sharded values identical to single-process | **FAILS** (8-18 cells of 408,845) |
| W2 — key agreement > 99.9% | HOLDS (99.9990%) |
| W3 — 4 shards > 100k pkt/s | **FAILS** (89,976) |
| W4 — 8 shards > 178k pkt/s = 1 Gbps | **FAILS** (107,435) |
| W5 — efficiency at 4 shards > 0.6 | **FAILS** (0.51) |

### Where the speedup goes — measured, not guessed

| suspect | measurement | verdict |
|---|---|---|
| IPC / pickling | 0.02s in, 0.03s out per shard vs 0.53s compute — **8%** | not the cause |
| Load imbalance | max/mean **1.57** (by src), **1.63** (by dst) at 12 shards | caps speedup at ~7.5x |
| Serial phases | partition + shuffle + merge: **13%** at 2 shards, **25%** at 12 | Amdahl |
| Parent-side result collection | inside the "parallel" stage timing | real, unseparated |
| Hardware | 12 logical CPUs, ~6 physical cores | ~1.2x from SMT, not 2x |

Per-shard compute in isolation runs at **73,460 pkt/s**, so the *algorithm* on
12 true cores with zero coordination cost would be around 880k pkt/s. The
entire gap between that and the measured 120k is coordination, not computation.

### What would actually reach line rate, and why it is not claimed

In a real sensor, packets never cross a process boundary: each shard reads its
own NIC queue via RSS or `AF_PACKET` fanout, which removes parent-side
partitioning, pickling and result collection — every serial term above. That
path is plausible and it is **not validated here**. Saying "it would work in
production" is exactly the move this repository exists to avoid.

The honest statement is: **672 Mbps measured, 1 Gbps not reached, and the
remaining gap is coordination overhead that a kernel-level fanout would remove.**

### Two findings worth more than the throughput number

**Sharding multiplies host capacity, and that changes results.** `max_hosts` is
a *per-instance* budget, so N shards hold N times as many hosts. On a 300-second
workload where a spoofed-source flood packs 300k unique sources into 5 windows,
the single-process run evicted **99,483 hosts** and the 4-shard run evicted
none — a 72% disagreement in output cells that looked exactly like a
correctness bug. It is not: it is a capacity difference, and comparing the two
requires matching total budget. The test suite now pins both behaviours.

**W1's failure is real but tiny.** 8-18 cells of 408,845 (0.004%) differ,
because each shard runs its own watermark, so which marginal records fall
outside the lateness budget depends on that shard's traffic. A global watermark
broadcast to shards would remove it; independent watermarks are the simpler
design and the error is bounded.

### A bug this caught

The first working version lost **17% of output rows**. Concatenating shard
outputs fed stage 3 a sequence that ran 0..T for shard 0, then jumped back to 0
for shard 1 — and the lateness budget discarded it. Flow tuples now carry an
emission timestamp and the shuffle does a k-way merge on it, restoring the
global order a single process would have seen. Without that, sharding looks
lossy when the real fault is an unordered shuffle.

---

## Experiment 06 — the full packet pipeline

Experiments 03-05 all begin from flow records, because CIC-IDS2017 ships them
pre-assembled. A diode enclave sees packets. `ingest/flow_assembler.py` closes
that gap, and running the whole chain exposed a problem the flow-level
experiments could not:

    packets -> visibility filter -> flow assembler -> streaming host-window -> detector

### Out-of-order flows are a real cost, not a footnote

A flow assembler emits a flow when it **expires**, not when it starts. A flow
beginning at t=10s and idling out at t=70s is emitted at t=70s but belongs to
the window containing t=10s. A windowed aggregator that assumes ordered input
discards those records — and the original `StreamingHostWindow` did worse than
discard them: it moved its window pointer *backwards*, corrupting every
aggregate after it.

| allowed lateness | flows kept | dropped late | loss | total latency |
|---|---|---|---|---|
| **0s** | 317,783 | 44,774 | **12.35%** | 60s |
| 5s | 342,755 | 19,802 | 5.46% | 65s |
| **15s** | 362,543 | 14 | **0.00%** | **75s** |
| 30s | 362,556 | 1 | 0.00% | 90s |
| 60s | 362,557 | 0 | 0.00% | 120s |

**Ignoring the problem costs 12.35% of all flows.** A lateness budget equal to
the assembler idle timeout (15s) reduces that to 14 flows out of 362,557, for
15s of additional end-to-end latency. That is the setting to ship.

| Prediction | Verdict |
|---|---|
| V1 — lateness=0 drops >5% of flows | **HOLDS** (12.35%) |
| V2 — lateness=15s drops <1% | **HOLDS** (0.004%) |
| V3 — F1 within 0.01 of oracle ordering | **HOLDS** (0.8995 vs 0.9003) |
| V4 — throughput > 100k packets/s | **FAILS** (47,968) |

### V4 failed, and the honest number matters more than the prediction

**47,968 packets/s** end-to-end, single-threaded, pure Python. Not the 100k I
predicted.

What that means in practice: at ~700-byte average packets, 48k pkt/s is roughly
**270 Mbps**. That is not line rate for a 1 Gbps peering link, and claiming
otherwise would be the easiest lie in this repository.

Two things make it addressable rather than fatal, and both should be said
plainly rather than implied:

- The pipeline is **trivially shardable**. All state is keyed by host, so N
  workers partitioned by `hash(host)` scale linearly with no cross-talk. Four
  shards clears 1 Gbps.
- The assembler alone runs at **348k packets/s**; the host-window stage is the
  bottleneck. A Rust or Go ingest path for those two stages is the obvious fix
  and is not built.

An honest 48k pkt/s with a named path to more is worth more than a fabricated
number that collapses under one question.

### Assembler behaviour on the one-way tap

| | |
|---|---|
| Packets observed (one-way) | 434,360 of 905,635 (48.0%) |
| Flows assembled | 362,557 |
| Closed by FIN/RST | 900 |
| Closed by idle timeout | 361,604 |
| Closed by active timeout | 0 |
| Flows evicted (bounded memory) | 0 |

**Only 900 of 362,557 flows are closed by observing a teardown.** On a one-way
tap you see the initiator's FIN but never the peer's, so timeouts carry
essentially the entire load. That makes the timeout policy a first-class design
parameter rather than a detail, which is why both are constructor arguments and
why the sweep above exists.

### One evaluation caveat

At lateness=0 the detector scores *higher* (0.9061 vs 0.8997 at 15s). That is
not evidence that dropping data helps — it is scored on a different, smaller
population of cells, since 12% of flows never arrived. Cross-lateness F1
comparisons are not like-for-like; the like-for-like comparison is the
oracle-ordering row, where the cost of realistic ordering is **−0.0008**.

### What this does and does not validate

This runs on **synthetic packets**, because CIC-IDS2017's freely-available form
is flow records and cannot exercise an assembler at all. So it tests the
*mechanism* — assembly, expiry, lateness, throughput — and is **not** a second
validation of the exp04 finding. That distinction is deliberate.

---

## Experiment 05 — streaming vs batch features

Experiment 04's whole result rests on 16 host-window features computed with a
pandas `groupby` — a batch operation over the entire capture. The PS is explicit
that the pipeline must be streaming with bounded latency, so exp04 only means
something if those features can be produced incrementally.

`features/streaming_host_window.py` does it in a single pass. Every estimator
starts **exact** and promotes to a sketch only when it outgrows a threshold
(set → HyperLogLog at 256 distinct; dict → Count-Min + Misra-Gries at 256).
Most hosts touch a handful of peers per window, so the common case is exact and
free; only the heavy hitters — scanners — pay approximation error, and a
scanner's fan-out does not need to be known to ±1.

| | batch (groupby) | streaming (single pass) |
|---|---|---|
| Throughput | 199,647 flows/s | **221,032 flows/s** |
| Memory | whole corpus in RAM | **2.58 MB** peak, sensor state only |
| Latency | end of capture | **60 s** (one window) |
| Deployable on a live link | no | yes |

### Agreement: 14 of 16 features are bitwise identical

| Feature | Pearson r | mean rel. err | bitwise equal |
|---|---|---|---|
| 14 features | 1.0000 | 0.00000 | **100%** |
| `hw_src_n_dports` | 1.0000 | 0.00130 | 81.3% |
| `hw_src_bytes_vs_baseline` | 0.9997 | 0.845 | 0.1% *(differs by design)* |

`hw_src_n_dports` is the only feature where the sketch actually engages — port
fan-out is the one quantity that regularly exceeds 256 distinct values in a
window, and that only happens for scanners. Relative error 0.13%.

`hw_src_bytes_vs_baseline` is **defined differently** in the two
implementations: the batch version does an EWM over the windows in which a host
appeared, the streaming version time-decays across silent gaps. The streaming
definition is the more defensible one — a host silent for an hour should not
carry a hot baseline — and we report the disagreement rather than tuning one to
match the other.

### Downstream: no measurable cost

| Feature source | binary F1 |
|---|---|
| host-window only, batch | 0.9812 |
| host-window only, **streaming** | 0.9812 |
| forward + host-window, batch | 0.9810 |
| forward + host-window, **streaming** | 0.9812 |

| Prediction | Verdict |
|---|---|
| U1 — all but the baseline correlate > 0.99 | **HOLDS** (worst r = 1.0000) |
| U2 — downstream F1 within 0.01 | **HOLDS** (+0.0001) |
| U3 — throughput > 50k flows/s | **HOLDS** (221k) |
| U4 — zero evictions at max_hosts=50,000 | **HOLDS** (0; 14,817 hosts seen) |

### The claim this licenses

> The 16 features that carry exp04's result are computable **on a live one-way
> link**: single pass, 221k flows/s single-threaded, 2.58 MB of state for
> 14,817 hosts, 60 s latency, and no measurable accuracy cost versus the exact
> batch computation.

Two honest notes. The throughput figure is flow-level, not packet-level — a
packet-level sensor would need this behind a flow assembler and that is not
built. And memory is bounded *by construction* via `max_hosts` LRU eviction,
but this corpus never reached the cap, so the eviction path is tested by unit
tests rather than by this run.

### A measurement bug worth recording

The first run of this experiment reported "peak traced memory 0.0 MB". Two
causes, both mine: a patch adding the traced pass silently failed to apply, so
a stale zero was printed; and the original design measured memory while
accumulating all 132,782 emitted rows in a list, which measures the *sink*
rather than the sensor. Memory is now measured on a dedicated pass that
discards emitted rows, which is what a real deployment does.

An implausible number should be checked, not published. 0.0 MB for 877k flows
was implausible.

---

## Experiment 04 — how much of the one-way gap is real?

Same corpus, same temporal split (aligned to a window boundary), plus 16
**host-window aggregate** features computed from forward-only columns:
fan-out, source-IP entropy, peer concentration, flow-arrival periodicity,
volume versus a causal per-host baseline. These are what a sensor *built* for a
one-way tap would keep; CICFlowMeter emits none of them.

| Condition | features | binary F1 | macro F1 |
|---|---|---|---|
| A — full visibility | 103 | 0.9793 | 0.3999 |
| C — one-way, CICFlowMeter features | 35 | **0.6903** | 0.3110 |
| **E — one-way, purpose-built sensor** | 51 | **0.9810** | 0.4660 |
| F — full visibility + host-window *(control)* | 119 | 0.9811 | 0.5593 |
| **G — host-window aggregates alone** *(control)* | **16** | **0.9812** | 0.5995 |

| Prediction | Verdict |
|---|---|
| T1 — E > C | **HOLDS** (0.981 vs 0.690) |
| T2 — E closes ≥ half the residual gap | **HOLDS** (closes 101%) |
| T3 — entropy/fan-out in E's top 10 by gain | **HOLDS** (5 of the top 10 are host-window) |

### All three predictions held, and the controls still undercut the framing

Taken alone, E says a purpose-built one-way sensor matches full visibility, and
exp03's dramatic −0.47 collapse was mostly an artefact of CICFlowMeter's
per-flow feature set lacking host context.

The controls say something less flattering:

- **F ≈ E.** Adding host-window state to the *full-visibility* model gains it
  nothing (0.9811 vs 0.9810). So the reverse channel adds nothing on top of
  windowed host state.
- **G ≈ E ≈ F.** Sixteen host-window aggregates **on their own, with no
  per-flow features at all**, reach 0.9812 — matching every other condition.

So the honest statement is not "one-way sensors can match full visibility." It is:

> **On CIC-IDS2017, windowed host state dominates the task. Once a model has it,
> both traffic direction and per-flow features stop mattering.** The visibility
> question, which exp03 made look decisive, largely dissolves.

### Why that is a finding about the corpus, not just the model

CIC-IDS2017's attacks run in dense temporal bursts. A 60-second window during a
DDoS or a portscan contains almost nothing but attack flows, so window-level
host statistics come close to answering "is this an attack window?" — which is
nearly sufficient for per-flow classification on this data.

That is legitimate sensor behaviour for volumetric attacks, and it is also a
known weakness of this corpus as a benchmark. It means these numbers would not
transfer to a stealthy, low-rate intrusion spread thinly across many windows,
and we should not claim they would.

Two things stop this being pure burst-detection: macro-F1 *rises* with the
host-window features (0.40 → 0.60), which co-occurrence alone would not
produce; and the top features by gain are the mechanistically expected ones
(fan-out, flows-per-source, distinct destination ports), not raw volume alone.

### What this still does not settle

TTL diversity, DNS query-name entropy and TLS client-fingerprint rarity need
packet-level data the flow CSV does not carry. Since the gap is already closed
without them, their value is now an open question rather than a missing piece.

The experiment that would actually settle the visibility question needs a
corpus with **low-rate, temporally diffuse attacks**, where window context
cannot substitute for per-flow evidence. CIC-IDS2017 is not that corpus.

**Experiment 10 built that condition and ran it. The paragraph above was right
to worry: see below — the host-window-alone result does not survive.**

---

## Experiment 10 — the bursty-corpus caveat, tested. Read this next to exp04.

Experiment 04's headline rests on CIC-IDS2017's attacks being bursty: a DDoS or
portscan fills a whole (host, window) cell, so a per-cell aggregate is close to
answering "is this an attack window?". We flagged that as the biggest hole in
the result. This closes it.

### The instrument

`ingest/diffuse.py` rearranges the **real** corpus rather than generating one.
Attack flows keep every per-flow feature as measured; only two things change:

1. **Temporal diffusion** — a campaign is re-timed to put `d` flows in a cell
   instead of its original burst.
2. **Host blending and hiding** — campaigns are re-homed onto internal hosts
   that already carry benign traffic, and placed in the windows where those
   hosts were *busiest*. This models a compromised insider running inside the
   victim's own noise. Without it, an attacker's cells are pure attack and the
   density knob measures nothing.

Attack volume is capped once at 15,000 flows so every density is physically
reachable (the corpus has only 15 internal hosts x 6,247 windows = 93,705
cells), and held constant across the sweep. Attack rate 1.6%.

### Binary F1 — attack vs benign

| flows/cell | dilution | benign flows in cell | A FULL | C MATCHED | E SENSOR | G HW ONLY |
|---|---|---|---|---|---|---|
| 60 | 0.408 | 188 | 0.983 | 0.937 | 0.935 | **0.869** |
| 17 | 0.245 | 172 | 0.982 | 0.984 | 0.979 | **0.816** |
| 5 | 0.189 | 125 | 0.937 | 0.979 | 0.936 | **0.780** |
| 2 | 0.199 | 59 | 0.942 | 0.994 | 0.940 | **0.776** |
| permuted | — | — | 0.496 | 0.496 | 0.496 | 0.496 |

### Macro F1 — per attack class, where the story is

| flows/cell | A FULL | C MATCHED | E SENSOR | G HW ONLY |
|---|---|---|---|---|
| 60 | 0.848 | 0.780 | 0.742 | **0.352** |
| 17 | 0.856 | 0.840 | 0.789 | **0.298** |
| 5 | 0.771 | 0.831 | 0.798 | **0.266** |
| 2 | 0.864 | 0.890 | 0.870 | **0.277** |

### Verdicts

| Prediction | Verdict |
|---|---|
| Z0 — every density physically reachable *(capacity control)* | HOLDS |
| Z1 — G >= 0.85 binary-F1 at the bursty end *(validity control)* | HOLDS (0.869) |
| Z2 — G loses >= 0.15 binary-F1 across the sweep | **FAILS** (0.093) |
| Z3 — at the diffuse end A beats G by > 0.10 binary-F1 | HOLDS (+0.166) |
| Z4 — the one-way tap costs more when attacks are diffuse | **FAILS** (-0.053 vs +0.046) |
| Z5 — permuted labels stay below 0.55 *(negative control)* | HOLDS (0.496) |

### What this changes

**The claim that fails.** exp04: 16 host-window features alone reached 0.599
macro-F1, the *best* of five conditions, beating all 103 full-visibility
features at 0.400. Here the same 16 features are the *worst* condition at
0.35 falling to 0.28, while full visibility holds 0.77-0.86.

The mechanism is structural. Host-window features are computed per cell, so
every flow in a cell gets the same vector. With 59 to 188 benign flows sharing
each attack cell, the attack is outnumbered 59:1 to 188:1 and no model can
separate it from its neighbours on those features alone. exp04 was not wrong -
it was measuring cells that were 98% attack.

**The claim that survives, and is strengthened.** The one-way tap still costs
nothing. Forward-only per-flow features (C) track or beat full visibility (A) at
every density. EKAGRA's actual thesis - that a diode-side sensor is viable - is
untouched by this result.

**So the architecture claim narrows to:** keep per-host state, but never run on
it alone. Windowed host state is what makes the one-way tap viable; per-flow
evidence is what still finds the quiet intrusions. Condition E ships both.

### Two honest problems with this experiment

**Z1 checked the wrong metric, and nearly hid the finding.** The validity control
asked for G >= 0.85 *binary*-F1 at the bursty end, and got 0.869. But on macro-F1
G was already at 0.352 there, against exp04's 0.599 - so the "bursty end" of this
sweep was never exp04's regime to begin with. Hiding attacks in busy cells
dilutes at *every* density, which is why Z2 then failed: G had already lost most
of its power before the density knob was turned. The dominant variable here is
dilution, not density, and the pre-registration should have said so.

**Z4 failed in a direction we cannot explain.** The one-way tap did not merely
cost less at low density - it went *negative*, with forward-only features beating
full visibility at three of four densities (0.994 vs 0.942 at the diffuse end).
Plausibly the backward-derived features add variance without signal at 1.6%
prevalence, or 150 trees under-fit a 103-feature model more than a 35-feature
one. Both are guesses. It is recorded as an unexplained inversion, not claimed
as a finding.

Dilution is also not monotone (0.41, 0.25, 0.19, 0.20): at the lowest density
the attack needs 9,800 cells and runs out of busy windows, so it starts landing
in quieter ones.

---

## Experiment 03 — the first real-corpus run

> Superseded in part by experiment 04 above: condition C here is handicapped,
> and the collapse it reports is largely explained by missing host context.

877,801 flows from the corrected CICFlowMeter re-extraction of CIC-IDS2017
(Zenodo 22016274). Temporal split, 614,461 train / 263,340 test.

| Condition | binary F1 | vs A |
|---|---|---|
| **A — full visibility** | **0.9877** | — |
| **B — deployed on a one-way tap** | **0.5222** | **−0.4656** |
| **C — retrained under the deployment profile** | **0.6833** | **−0.3044** |
| D — as C, 1:16 flow sampling | 0.6917 | −0.2960 |

| Prediction | Verdict |
|---|---|
| S1 — B collapses relative to A | **HOLDS** (−0.47) |
| S2 — C recovers to within 0.10 of A | **FAILS** (−0.30 remaining) |
| S3 — drop ≥ half the synthetic 0.22 | **HOLDS** (0.47, more than double) |

### The finding, and it is not the one the synthetic study predicted

> On real traffic a detector trained with full bidirectional visibility loses
> **0.47 binary-F1** when deployed on a one-way tap — more than twice the
> synthetic estimate. And **visibility-matched retraining recovers only about a
> third of it** (+0.16 of 0.47), leaving a **0.30 residual gap**.

The generated study concluded that retraining under the deployment profile
recovers essentially everything (0.938 vs 0.926 baseline, a +0.01 *surplus*).
**On real traffic that is false.** The reverse channel carries information that
forward-side features do not replace.

This is the most important result in the project, and it only appeared because
the real corpus was run. It also means the headline previously written into
`ARCHITECTURE.md` was wrong, and it has been rewritten.

### What the generated study did and did not get right

| | generated | real |
|---|---|---|
| Direction of the effect | collapse | collapse ✓ |
| Magnitude of the collapse | −0.22 | **−0.47** ✗ |
| Recoverable by retraining? | yes, fully | **no, ~1/3** ✗ |

A controlled instrument that gets the sign right and the magnitude off by 2x,
and the central claim backwards, is worth having for iteration speed and worth
nothing as evidence. That is now stated wherever the synthetic numbers appear.

### Caveats, in order of how much they could change the conclusion

1. **Condition C is handicapped, and this is the big one.** It uses the 35
   forward-observable features *CICFlowMeter happens to compute*. A
   purpose-built one-way sensor would compute things CICFlowMeter does not —
   source-IP entropy, TTL diversity, fan-out cardinality, arrival periodicity —
   and the synthetic pipeline **did** have those. So the true recoverability
   sits somewhere between C's 0.683 and A's 0.988, and this experiment does not
   locate it. Extracting proper forward-side features from the PCAPs is the
   next experiment and it is the one that decides how big the real claim is.
2. **Test-period composition.** The temporal split puts Friday's Botnet, DDoS
   and Portscan entirely in test — 170,873 flows, 64.9% of the test set, in
   classes the model never saw. All three conditions face this identically, so
   the *comparison* holds, but the absolute numbers describe a novel-attack
   scenario rather than a steady-state one.
3. **Multi-class F1 is nearly vacuous here** (A = 0.4666) because after removing
   unseen classes the test window contains almost only BENIGN and Infiltration
   variants. Binary F1 is the headline for that reason.
4. **Ignore D's macro-F1 of 0.9986.** The 1:16 sample has its own, much smaller
   label space, so that number is not comparable to the others. Its binary F1
   (0.6917) is.
5. Benign flows are subsampled to 30%; all attack flows are kept. Identical
   rows across conditions.

### Preprocessing decisions that materially affect the numbers

- **Source and destination IP excluded from every feature set.** The testbed
  uses fixed attacker addresses; a model given the IPs memorises them and
  reports a meaningless near-perfect score.
- **Temporal split, never random.** A random split puts flows from the same
  attack episode on both sides.
- **`X - Attempted` classes kept separate**, not merged back into `X`. Merging
  would undo part of the correction this corpus was chosen for.
- **Bidirectional aggregates dropped, not kept.** `Flow IAT Mean` is not
  "forward IAT with noise" — a one-way sensor computes a different quantity
  that this CSV does not contain. 35 features fall in this category; keeping
  them would have understated the collapse substantially.

---

## Experiment 01 — the generated-traffic study

Retained because it is a fast controlled instrument and because its failures are
instructive. **Its conclusions do not survive contact with the real corpus** —
see above.

| Condition (at DIODE_ONEWAY) | macro-F1 |
|---|---|
| A — full visibility | 0.9263 |
| B — deployed on one-way tap | 0.7108 |
| C — visibility-matched retraining | 0.9379 |
| D — "unidirectional-native" features | 0.9266 |

| Prediction | Verdict |
|---|---|
| P1 — B collapses at every degraded rung | PARTLY |
| P2 — C recovers but stays below A | **REFUTED** |
| P3 — native features beat retraining *(the original claim)* | **REFUTED** |
| P4 — enrichment loss costs more than direction loss | **REFUTED** |

Two secondary results from this study that the real corpus could not test:

- Removing a 55%-recall IP-reputation feed **improved** results (0.926 → 0.971).
- 1:16 flow sampling barely hurt once training was visibility-matched — echoed
  on real data (D ≈ C, 0.692 vs 0.683).

### Errors found and fixed during this study

1. **Feature withholding.** The bidirectional baseline was missing name-entropy
   and regularity features, making the "native" set look better for reasons
   unrelated to visibility. Adding them erased a +0.05 advantage entirely.
2. **Non-determinism.** Python salts string hashing per process, and that
   reached the sketches, the flow sampler and the reputation oracle. Identical
   runs produced macro-F1 between 0.90 and 0.97. Fixed with a stable hash;
   `tests/test_reproducibility.py` fails if it regresses.

---

## Reproducing

```bash
python experiments/exp01_ablation.py && python experiments/make_figures.py
python experiments/exp03_cicids_ablation.py && python experiments/make_figures_real.py
```

```bash
python experiments/exp04_forward_features.py
python experiments/exp05_streaming_equivalence.py
python experiments/exp06_packet_pipeline.py   # no corpus needed
python experiments/exp07_sharded_throughput.py  # no corpus needed
```

exp01 runs in ~40s with no downloads. exp03 needs the 1.4 GB corpus (~9 min);
exp04 runs five models over it (~19 min). Tests: `python -m pytest tests/ -q` (113 passing).
