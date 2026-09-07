# Judge Q&A bank — SIH 2026 Grand Finale

How to use this: **rehearse the answer, do not read it.** Each entry has a
spoken answer of two or three sentences and the file or number behind it. If you
cannot say where a number comes from, you do not yet own that answer.

Two rules that matter more than any individual answer:

1. **If you do not know, say so, then say what you would do to find out.** A
   judge who catches you bluffing discounts everything else you said. A judge
   who hears "we did not test that, and here is how we would" hears a
   researcher.
2. **Never inflate a number under pressure.** Every figure below is printed by a
   run in the repository. If you round 0.869 up to "about 0.9" and a judge opens
   the file, you have just made your own evidence look unreliable.

---

## Part 1 — the five that can sink you

### Q1. How much of this did AI write?

**Say:** "I used an AI assistant heavily, as a pair programmer, and I am not
going to pretend otherwise. What is mine is the experimental design — the
pre-registered predictions, the controls, the decisions about what to believe
and what to throw away. Ask me about any file in either repository and I will
tell you why it is shaped the way it is."

**Then be able to do it.** This is the highest-risk question in the room and the
only defence is competence. Before December, walk every file in
`ekagra/src/` and `kalachakra/src/` until you can explain each design decision
unprompted. **Anything you cannot explain, delete or learn.** A smaller project
you fully own beats a larger one you do not.

Worth adding if the questioning continues: "The refutations are the proof.
An assistant asked to make us look good would not have produced 33 refuted
predictions out of 82, including one that killed our own headline claim and a
sweep that caught us under-reporting our own result."

### Q2. Why not just deploy Suricata or Zeek?

**Say:** "Both assume they can see a bidirectional conversation. Zeek's own
documentation is explicit about what happens when it cannot: it records the
connection state as **S0** - 'connection attempt seen, no reply' - which is the
state it uses for split routing and for a sensor that only sees one side. On a
diode tap that is not an edge case, it is every single connection. Zeek cannot
distinguish a completed session from a failed connection attempt, because the
evidence that separates them is on the other side of the diode."

**Backing:** exp03 — a model trained on bidirectional features drops 0.988 →
0.522 binary-F1 when deployed on a one-way tap. Zeek's `conn.log` state values
are documented in the Book of Zeek; S0 and the split-routing case are described
in Zeek's own "What is 'Weird' in Zeek?" note.

**The follow-through, if they push:** "So the honest comparison is not 'we beat
Zeek'. It is that Zeek is the right tool where it can see both directions, and
the diode-side position needs a sensor built for it. What we measured is how
much of the loss is recoverable there, and by what."

### Q3. Isn't this just XGBoost with extra steps?

**Say:** "The classifier is deliberately boring — gradient boosting on tabular
features, because a fancier model would be an unmeasured variable. The
contribution is four things around it: measuring what a one-way tap actually
costs, the host-window feature set that recovers it, conformal abstention so the
system can say 'I do not know', and a tamper-evident evidence chain the browser
verifies independently. None of those are the model."

**If pushed on novelty:** "The transferable part is the method — characterise
what your tap can observe, then train under that profile. That applies to any
sensor placement, not just ours."

### Q4. CIC-IDS2017 is a known-flawed dataset. Your 0.98 looks too good.

**Say:** "Agreed on both counts. We use the corrected re-extraction published on
Zenodo after Engelen and colleagues documented the labelling and feature defects
in the original. And 0.98 is binary-F1 on a subsample that is 49% attack — it is
not a deployment number. The honest figure is macro-F1, which is 0.40 to 0.60,
and we say so wherever the number appears."

**Backing:** Zenodo record 22016274. Engelen et al. (WTMC 2021) documented
mislabelled attacks, packet misorder and duplication, and a flow-construction
bug in CICFlowMeter that terminated a TCP flow on a single FIN instead of the
mutual FIN exchange. `RESULTS.md` reports macro-F1 beside every binary-F1.
exp10 is the strongest version of this answer: when we made the attacks
realistic, our best condition became our worst.

### Q5. What have you actually built, versus proposed?

**Say:** "EKAGRA is about 12,100 lines with 288 passing tests; KALACHAKRA about
4,000 with 100. Thirteen experiments, each with predictions written down before the
run and verdicts printed by the run itself. One command brings the whole sensor
up with a live console. Nothing in our deck is a plan — it is all measured, and
where it failed we say what failed."

---

## Part 2 — methodology and honesty

### Q6. Why write predictions down before running?

**Say:** "Because otherwise you fit the story to the result. If we had not
pre-registered, exp07 would have become 'sharding scales well' instead of
'sharding reaches 672 Mbps, not the 1 Gbps we claimed'. The verdict is printed
by the run, so we cannot quietly move the goalposts."

**Backing:** 82 predictions across both projects, **33 refuted** — a 40% failure
rate that would be impossible to fake in the direction of looking good.

### Q7. Why use generated traffic at all?

**Say:** "For questions where we need ground truth that no capture contains. You
cannot observe the branch that did not happen, so counterfactual pairs have to
be constructed. We use it as a controlled instrument and say so — every claim
that matters is also run on the real corpus."

**Backing:** exp01 (generated) and exp03/exp04 (real) test the same ladder. The
synthetic study got the *direction* right and the *magnitude* wrong, which is
exactly what a controlled instrument is for.

### Q8. How do you know your temporal split does not leak?

**Say:** "We split on a window boundary, not an arbitrary timestamp, because a
window straddling the cut would carry aggregate context across it. The label
space is defined from the training set alone, so classes absent from training
are excluded from multi-class scoring rather than silently counted as errors."

**Backing:** exp03 — 23 learnable classes, and 170,873 test flows fall into
classes never seen in training. We report that number rather than hiding it.

### Q9. Why is macro-F1 so much worse than binary-F1?

**Say:** "Because the corpus is dominated by a few volumetric classes. Binary-F1
asks 'attack or not', which the big classes answer. Macro-F1 weights every class
equally, including ones with eleven examples. The gap is the honest measure of
how much we are riding on DoS traffic."

### Q10. Your test set has classes the model never trained on. Isn't that broken?

**Say:** "It is realistic — a campaign in the last 30% of the capture that never
appeared earlier. We handle it by scoring multi-class F1 only over learnable
classes and binary F1 over everything, and we report both counts."

---

## Part 3 — EKAGRA technical

### Q11. What exactly is a host-window feature?

**Say:** "For each host in each 60-second window we compute sixteen aggregates:
fan-out, distinct peers and ports, source-IP entropy on the destination side,
peer concentration, forward packets and bytes, inter-arrival mean and
coefficient of variation, and volume against that host's own causal baseline.
They describe what a machine is doing, not what one connection looks like."

### Q12. Why 60 seconds?

**Say:** "It is a parameter, not a discovery. 60 seconds plus a 15-second
lateness budget gives 75 seconds of alert latency, which we state as a cost. We
have not swept it, and I would not claim it is optimal."

**This is a good place to be honest** — a swept window would be a genuine
improvement and it is not built.

### Q13. Why sketches instead of exact counts?

**Say:** "Bounded memory. An exact distinct-peer count per host per window grows
with traffic; HyperLogLog and Count-Min do not. We start exact and only promote
to a sketch above 256 distinct values, so most cells are exact anyway."

**Backing:** exp05 — 877,801 flows in **2.58 MB** peak state at 225,907 flows/s,
and **14 of 16 features are bitwise identical** to the exact batch computation.

### Q14. What is the sketch's error, and does it matter?

**Say:** "Fourteen features reproduce exactly. One differs in 19% of cells with
correlation 1.0000, and one differs by definition — the baseline feature, where
the streaming version is causal and the batch version can see the whole capture.
Neither reaches the model: F1 differs by 0.00001 and 0.00014."

### Q15. What is the lateness budget for?

**Say:** "A flow assembler emits a flow when it expires, not when it starts, so
a flow beginning at t=10 and idling out at t=70 arrives after its window has
closed. Ignoring that discards 12.35% of flows. A 15-second budget reduces it to
14 flows out of 362,557, for 15 seconds of extra latency."

**Be ready for the follow-up:** "Did it improve accuracy?" — **No.** F1 moved
0.007, and prediction V4 was refuted. The flows we recovered were short ones the
host window had already counted.

### Q16. What happens under a spoofed-source flood?

**Say:** "The host table is bounded by `max_hosts` with LRU eviction, and
evictions are counted and reported rather than silent. We found this the hard
way: a sharded run and a single-process run disagreed on 72% of output cells,
which looked exactly like a correctness bug. It was a capacity difference —
`max_hosts` is per-instance, so N shards hold N times as many hosts."

### Q17. What is conformal prediction and why Mondrian?

**Say:** "It converts a score into a prediction set with a coverage guarantee —
at alpha 0.1 the true label is in the set 90% of the time. Mondrian means a
separate threshold per class. We tried the simpler marginal version first and it
reported 0.883 coverage while abstaining on 95 to 100% of six of seven classes.
It was answering ddos and giving up on everything else."

**Backing:** exp08 — Mondrian gives 90.8% coverage at 9.1% abstention with
expected calibration error 0.0007, and 99.5% accuracy on the alerts it does
answer.

### Q18. What does abstention mean for an operator?

**Say:** "The alert is raised but marked ABSTAIN — it goes to a human queue
rather than an automated response. It is the system saying 'something is here
and I will not name it'. At 9.1% that is about one alert in eleven."

### Q19. What does the evidence chain actually prove?

**Say:** "That no entry has been altered since it was written, and that altering
one invalidates every entry after it. It proves integrity, not authorship — the
HMAC covers authorship but its key stays in the enclave, so the browser cannot
check it. We show the HMAC without claiming to verify it."

**The honest limit, say it before they ask:** "A producer who rewrote the entire
chain would still verify. That is what comparing the anchor against an
independently held digest is for, and that comparison is an operational
procedure we specify rather than code we ship."

### Q20. Why does the browser re-derive the hashes instead of trusting the server?

**Say:** "Because a verifier that trusts the producer verifies nothing. The
console rebuilds each entry's canonical form and re-hashes it with WebCrypto. In
live mode we also ask the server separately, so you see two independent
implementations in two languages agreeing — and disagreeing when you tamper."

**Demo note:** the tamper button edits the browser's copy only, so the server
still reads intact and the two *correctly* disagree. Explain that before
clicking, or it looks like a bug.

### Q21. You claim 672 Mbps. The link is 1 Gbps. Isn't that a fail?

**Say:** "Yes, and we put the number on the slide rather than the ratio. We need
178,571 packets per second at this packet size and we measured 119,918. We also
measured where it goes: per-shard compute alone is 73,460 packets per second, so
the algorithm on twelve real cores would be near 880k. The entire gap is
coordination, because a parent process feeds every shard."

**The fix, and why we do not claim it:** "In a real sensor each shard reads its
own NIC queue via RSS or AF_PACKET, which removes every serial term we measured.
That is plausible and unvalidated, so we are not claiming it."

### Q22. How do you know the sensor is really read-only?

**Say:** "Two tests, one static and one dynamic. The static one fails the build
if anything in the detection path imports socket, requests, urllib or similar.
The dynamic one replaces the socket constructor with something that raises and
runs the real pipeline — if any component tries to open a socket, the test fails
with a traceback pointing at it."

**Backing:** `tests/test_readonly_constraint.py`. The API is exempted
explicitly, and the exemption is justified in that file's docstring: the API
never imports ingest, every route is GET, and it binds loopback by default.

---

## Part 4 — the low-rate experiment (expect focus here)

### Q22b. Reading that paper changed your code. How?

**Say:** "Engelen's CICFlowMeter finding is that it closed a TCP flow on a
single FIN when it could see both directions and should have waited for the
mutual exchange. That made us check our own assembler, and we had the
mirror-image bug: we closed on the FIN, but a real stack sends a final ACK
afterwards, and on a one-way tap that ACK is the last packet of the session. It
was landing on an empty table and opening a second flow for the same 5-tuple -
so every cleanly closed session counted twice, inflating two of the sixteen
host-window features our result rests on."

**The honest part, say it unprompted:** "It changed no published number.
Our generator does not emit that final ACK and CIC-IDS2017 ships flow records,
so neither corpus could exercise the path - 845,322 flows either way. The fix
matters for real packet capture, which is the deployment we are arguing for, and
we are not going to claim an improvement we did not measure. It also told us our
own generator is unrealistic, which is now a recorded gap."

### Q23. Why re-time real flows instead of generating a low-rate corpus?

**Say:** "Because generating one would let us decide the answer. Re-timing the
real corpus keeps every per-flow feature exactly as measured and changes only
when an attack appears and which host it comes from. Density becomes the single
variable."

### Q24. Re-homing attacks onto benign hosts sounds like you engineered the result.

**Say:** "It models a compromised insider instead of CIC-IDS2017's dedicated
external attacker addresses, which is the actual threat model for a critical
network. And without it the knob measures nothing — an attacker-only cell stays
trivially separable however slow the attack is. We report the transform's
statistics so you can judge it: attack cells ended up holding 59 to 188 benign
flows."

**If pushed:** "It also cuts against us. The manipulation makes the task harder
for our own preferred condition, and that condition is the one that failed."

### Q25. What did exp10 actually refute?

**Say:** "Our own headline. In exp04 sixteen host-window features alone were our
best condition at 0.599 macro-F1, beating all 103 full-visibility features. Once
attacks share cells with benign traffic, those same features are our worst
condition at 0.28. The mechanism is structural — every flow in a cell gets the
same aggregate vector, so when the attack is outnumbered 59-to-1 inside its own
cell, no model can separate it."

**What survived — say this in the same breath:** "The one-way tap result held.
Forward-only features tracked or beat full visibility at every density. The
claim this project is named for is untouched; the over-strong secondary claim is
now bounded."

### Q26. Two of your six predictions failed there. Explain.

**Say:** "Z2 failed because the host-window features had already lost most of
their power at the bursty end — hiding attacks in busy cells dilutes at every
density, so the density knob only added 0.093 more. That means our validity
control checked the wrong metric, and we wrote that down. Z4 failed in a
direction we cannot explain: forward-only features beat full visibility at three
of four densities. We record it as an unexplained inversion rather than claiming
it as a finding."

**This is a strength if delivered calmly.** Most teams cannot name a flaw in
their own control.

---

## Part 5 — KALACHAKRA

### Q27. What is a world model here, concretely?

**Say:** "A graph encoder over the host-interaction graph produces a latent
state; a transition model advances that latent given an action; we roll forward
K steps with no new observations and score whether the trajectory reaches
compromise on the MITRE ATT&CK stage ladder. It predicts state, not labels —
that is the distinction the problem statement asks for."

### Q28. Your world model loses on lead time. Why show it?

**Say:** "Because an evaluator who runs the repository finds it in one command.
A tuned LSTM gives 3.35 windows of warning at 76% detection; the world model
gives 0.26 at 12%. We report the curve. The capability that survives is a
different one — answering what happens if we intervene, which no detector can
answer at all."

### Q28b. How does it compare to a simple baseline?

**Say:** "Badly, on detection, and the problem statement asks so we measured it.
Window-level F1: logistic regression 0.606, LSTM 0.712, our world model 0.412.
It also loses on AUC, 0.784 against 0.938. It is a forward simulator scored by
rollout risk rather than a window classifier, which is a real distinction and
not a good enough answer on its own."

**Then move to the ground you hold:** "The case for this architecture is not
detection. It is that you can ask it what happens if you act, and no baseline in
that table can answer that at all - the action-aware LSTM given the same
intervention as an input sits at a coin flip. We put the losing benchmark in the
repository because an evaluator finds it in one command."

**Backing:** `exp01_leadtime.py` prints the table; threshold swept on train,
applied to test. GBDT overfits hard there too - 0.971 train, 0.516 test.

### Q29. What is the counterfactual, and how can you possibly validate it?

**Say:** "800 matched pairs, each episode played twice from a bit-identical
prefix, differing only in whether we isolate the host. You cannot observe both
branches in a real capture, which is exactly why counterfactual ground truth has
to be constructed — and we say so rather than implying we measured it in the
wild."

### Q30. Why is the action-aware LSTM at chance? Isn't that a strawman?

**Say:** "It receives the action as an input feature, so no. It sits at 48% —
a coin flip — because conditioning a discriminative model on an action it only
ever saw correlated with outcomes does not teach it to reason about intervening.
That is what the number is evidence of: not that we rank well, but that the
LSTM never learned the intervention at all."

### Q31. Can it tell me which host to isolate first?

**Say:** "No, and that is the honest scope. It predicts an average treatment
effect, not a per-host one — it says isolating helps in 94% of cases, with
essentially zero correlation with which interventions actually work. We attacked that four times: more
data, FiLM conditioning, supervising the paired difference, and finally an
oracle run trained on the evaluation target itself. That last one still gave
+0.011, so the limit is structural."

### Q31b. Your 94% — is that accuracy?

**Say:** "No, and we relabelled it once we worked that out. It is the fraction
of cases where the model predicts isolating reduces risk. It never compares
against an outcome. Isolation genuinely helps in every pair our generator makes
— the true containment probability runs 0.31 to 0.75, never negative — so the
true sign is always positive and a constant 'always isolate' predictor would
score 100% on the same measure."

**Then say what it does show:** "The number is evidence about the baseline, not
about us. An action-aware LSTM given the same action as an input sits at 48%, a
coin flip — it never learned that the intervention does anything. Against the
realised binary outcome both sit near chance, because the outcome is a single
noisy draw. We put the 100% trivial baseline on the slide next to our 94%."

**Backing:** `exp13_demo_trajectories.py` computes and labels all three numbers;
the console shows the trivial baseline beside ours.

### Q31c. The PS asks for SHAP values or attention. You have neither.

**Say it first, before they find it:** "Correct — we have neither, and we are
substituting deliberately rather than quietly. There is no attention to read
off: the encoder is normalised-adjacency message passing. And SHAP is a
dependency plus thousands of forward passes per explanation."

**Then the argument:** "We ship integrated gradients, and the reason that is a
substitute rather than a hand-wave is one property — **completeness**. The
attributions provably sum to `f(input) − f(baseline)`, which is the same axiom
SHAP's efficiency property gives you. The difference is we can *check* it, and
SHAP users mostly cannot. We check it three times: in the library's tests, in a
test over the forty shipped cases, and again in the browser — the console
recomputes the residual from the numbers on screen, and if it fails it prints
'treat this ranking as indicative only' instead of a ranking."

**If they push on the baseline:** "Good question, because the obvious choice is
wrong here. Integrated gradients explains `risk − baseline`, so the reference
decides what the numbers mean. We measured it: an empty graph scores **0.768**
on this model — it finds 'nothing is happening' alarming, which is a real
calibration weakness we would rather tell you about. So zeros would explain only
the sliver above 0.77, against a state the network is never in. We reference the
mean of 194 benign windows instead, which scores 0.027, and every result records
which reference produced it."

**The best thing to volunteer here:** "Completeness earned its keep immediately.
Our first run used a flat 32 integration steps and looked fine — until we
checked. Twelve of forty cases had a residual larger than 2% of the gap, and on
one quiet case the contributions summed to **−0.17 against a gap of +0.008** —
wrong sign, twenty times too large. The risk head clamps and saturates, so
coarse quadrature walks past the kinks. We made the step count adaptive and all
forty now converge at 52 steps on average. A gradient×input attribution would
have handed us a confident ranked list for that case and nothing would have told
us it was noise. That is the entire argument for picking a method with a
checkable axiom."

**The limit, stated before they ask:** "It explains the model's function, not
the network. If the model learned a spurious correlate, attribution reports the
spurious correlate faithfully — that is true of SHAP too. It is on screen."

**Backing:** `src/kalachakra/explain/attribution.py`,
`tests/test_attribution.py`, `tests/test_demo_payload.py`, and the attribution
panel in the console.

### Q31d. You claim JA3. Chrome randomises extension order — doesn't that break it?

**This is the best question a TLS-literate judge can ask, and we have the
measurement.** "Yes, completely, and we found that on our own capture rather
than in a paper. We ran 148,000 packets of ordinary browsing through the sensor.
97 ClientHellos gave **92 distinct JA3 fingerprints** — almost one per
connection. Chrome has randomised extension order since v110 to stop protocol
ossification, and JA3 hashes extensions in wire order."

**Then the fix:** "That is why the PS says 'JA3/JA3S **or JA4**'. JA4 sorts the
cipher and extension lists before hashing. On the identical 97 hellos it gives
**7** fingerprints — and 7 is exactly the number of distinct extension *sets*,
so JA4 is recovering the real client stacks. The sensor defaults to JA4; JA3 is
still selectable because published corpora like abuse.ch are indexed by it."

**The number that proves it matters:** "`hw_src_tls_fp_novel` has mean 0.0039 on
that capture — correctly near zero for benign traffic. Under JA3 it would have
been close to 1.0, so the encrypted-C2 head would have fired on every
connection my laptop made."

**If they push further — and this is the answer that should end the exchange:**
"In the same capture UDP/443 beat TCP/443 80,291 to 32,069, so most HTTPS is
HTTP/3. We wrote that off as a hard ceiling and we were wrong. **QUIC Initial
packets are decryptable by any observer** — RFC 9001 derives their keys from the
Destination Connection ID, which is in the clear, using a published salt. The
encryption is there to stop middleboxes ossifying the handshake, not to hide it.
We implemented it, and 24% of the handshakes in that capture are HTTP/3 we now
fingerprint as JA4 with transport `q`."

**Pre-empt the obvious challenge:** "This is not payload decryption, which the
PS forbids. The 1-RTT keys protecting application data come from the TLS
handshake and a passive observer cannot have them. We decrypt exactly the one
message that is deliberately readable and stop. And we pin correctness to
RFC 9001 Appendix A's own test vectors rather than our own output — a key
derivation bug returns plausible nonsense instead of an error, so self-checking
would prove nothing."

**Backing:** `ingest/wire.py`, `RESULTS.md`, and `python analyse_pcap.py` on any
capture the judge cares to hand you.

### Q31e. Did you test the parsers on anything hostile?

**Say:** "They are the only code in EKAGRA that reads adversary-controlled
bytes, so they get the most hostile tests we have. `test_wire.py` fuzzes with
random input, bit-flipped valid messages, and every truncation of both formats,
and asserts no exception escapes. The specific one worth naming is the DNS
compression-pointer loop: a crafted packet can point a label at itself, which
hangs a naive parser — and a sensor you can hang with one packet fails exactly
when someone wants it to. Pointers must move strictly backwards, which makes a
cycle impossible rather than merely unlikely."

### Q31f. Does the DGA detector work on real traffic, or only on yours?

**Lead with the number that failed.** "We ran a real 812 MB capture through it —
279 distinct benign domains — and the most important result is a refutation. A
threshold calibrated on our *generated* benign names flags **89.6% of real
benign names**. Not 5% — nearly ninety. Any threshold tuned on our generator is
meaningless on a real network. That is the strongest argument in the project for
why the generated corpus is a controlled instrument and not a substitute for
data, and it is why calibration happens on observed traffic."

**Then the separation, by family:** "We tested against reimplementations of
published DGA families, because testing against our own generator would be
circular. Uniform random names — exactly what our generator makes — score 0.979.
**Banjori scores 0.747**, and only the bigram model gets it there; raw entropy is
at 0.584, barely above chance. Banjori rewrites four characters of a real domain
and keeps the rest, so there is very little for character statistics to grip."

**The finding worth volunteering — it shows we measure our own components:**
"Our causal bigram model looked marginal on a first, smaller capture, and the
prediction attached to it was written as a deletion test. On 279 names it is the
strongest feature on four of six families. We measured why: it has a **warm-up
curve**. Below about 50 distinct benign names it is near chance; by 200 it is at
0.95. So the DGA head needs history before it is worth switching on, and we can
tell an operator how much."

**If they ask about the operating point — a good judge will:** "AUC hides
deployment cost. Catching 90% of even the easiest family costs more than 5%
false positives on all benign DNS — 5,000 false alerts an hour on a
100,000-query network. That is precisely why the conformal abstention layer is
there rather than a bare threshold."

**One correction we made on ourselves:** "The first version of the warm-up table
fitted and scored on the same names at the largest size and reported 0.999. That
was a leak. We caught it, fixed it so every size leaves at least 40 unseen
names, and the honest peak is 0.976."

**Backing:** `experiments/exp11_dga_real_benign.py`, runnable against any
capture a judge hands you. No query name from our capture is in the repo.

### Q31g. Have you tested KALACHAKRA on anything other than your own generator?

**This is the question that used to have no good answer, and now does.** "Until
recently, no — every KALACHAKRA number was measured on data we generated, which
is a closed loop. We ran it on **CTU-13: thirteen real botnet captures from CTU
Prague, 19.9 million flows**, leave-one-scenario-out so every test episode is a
network and a malware family the model never saw."

**Lead with the loss.** "Our lead-time claim was already refuted on synthetic
data — a tuned LSTM beat us 3.35 to 0.26 windows. **The refutation replicates on
real data.** The world model catches **5 of 12** real infections at under 10%
false alarms. Gradient boosting catches **7 to 9**. Logistic regression still
wins AUC and F1. So the synthetic result was not an artefact of our own
dynamics, which is what we most wanted to know."

**If they have read an older version of our own repo saying 1 of 12:** "Good
catch, and that correction is ours — see Q31i. We published 1 of 12; the honest
number is 5 of 12. We found it, we explain why, and we corrected it upward
against our own interest."

**Volunteer the prediction we got wrong.** "We predicted real lead times would
be *shorter* than synthetic, reasoning that real onsets are abrupt where our
generator ramps. They are **longer** — 8.67 against 3.35 windows. We were wrong
about the direction, and the useful consequence is that our generator is
pessimistic about the very quantity it was built to study."

**The finding that applies to everyone, not just us:** "Fold variance dominates
everything. All four methods span roughly 0.03 to 0.99 AUC across the thirteen
captures. At a standard deviation of 0.33 the four mean AUCs are not
distinguishable from each other. **Cross-network transfer on this corpus is
close to a coin flip per capture** — that is a statement about the problem, not
about our model, and any team claiming a clean cross-network number on CTU-13
should be asked for their per-fold spread."

**If they ask why not test the counterfactual on it:** "Because no real capture
contains the branch that did not happen. You cannot observe what would have
followed had the host been isolated. That claim stays on constructed pairs and
we say so rather than reporting a real-data number that is not measuring it.
CTU-13 also has no kill-chain stage labels — botnet, normal, background only —
so the ATT&CK stage head degenerates to compromised-or-not there."

**Backing:** `experiments/exp14_ctu13_leadtime.py`, `data/ctu13.py`. The world
model trainer is *extracted from* experiment 01 rather than reimplemented, so
synthetic and real runs provably use the same objective — otherwise the
difference between them would be unattributable.

### Q31h. Did you actually tune the world model, or just run defaults?

**The obvious challenge to the CTU-13 loss, and we ran the experiment rather
than argue.** "Fair question — experiment 14 used hyperparameters chosen on
generated data. So we did a proper tuning pass. It did not help: **1 of 12
before, 1 of 12 after.** AUC moved 0.663 to 0.677 against a fold-to-fold
standard deviation of 0.35, which is noise."

**The part that matters methodologically:** "Selection was **nested**. The
naive way to tune is to try configurations and keep whichever scores best under
leave-one-scenario-out — but that is tuning on the test set, and with twelve
attack episodes it would very likely turn 1/12 into 3/12 out of pure search. So
the configuration is chosen on a *separate inner validation capture* and the
test fold is never seen during selection. No number we report has seen its own
test fold."

**Two results worth volunteering:** "Eleven of twelve folds picked a
non-default configuration, so the settings really were wrong for real data —
and correcting them still did not help. Second, no configuration won a majority
of folds, so there is no single tuned model to ship. On this corpus the variance
between captures dwarfs the difference between configurations."

**Then volunteer that this pass had a flaw, and we found it:** "That tuning pass
selected on AUC. We later proved AUC is the wrong criterion here — see Q31i. The
conclusion survived; the method did not."

**Backing:** `experiments/exp15_ctu13_tuning.py`.

### Q31i. Your repo says 1 of 12 in one place and 5 of 12 in another. Which is it?

**5 of 12, and the discrepancy is a correction we made to ourselves.** Do not be
defensive about this — it is the strongest single story in the submission.

"We swept the one hyperparameter experiment 15 had left alone, the rollout
horizon. At the setting that should have reproduced our published row, it caught
4 of 12 instead of 1. So we stopped and found out why."

**The control is what makes this credible:** "Gradient boosting has no training
randomness on this data, so it is a deterministic control. In the same run, on
the same folds, it reproduced our published row to the digit — 7 of 12, mean
lead 8.08, AUC 0.624. That proved the data, labels, features, folds and scoring
were identical, and isolated the difference to the world-model path alone."

**Then rule out the obvious explanation:** "Six seeds. The world model caught 4
of 12 on every one, with zero variance. It was not noise."

**The cause:** "Training length. And the direction is the point — training
longer raises AUC (r = +0.78) and *lowers* the detection count (r = −0.45). The
two metrics move in opposite directions. Our published row was measured at 40
epochs, where AUC is best and detection is worst, and nothing in the saved
payload recorded the epoch count. That last part was a genuine reproducibility
fault and we fixed it: every knob that can move a number is now written to the
verdicts file."

**Why it matters beyond the number:** "Experiment 15 tuned by AUC. AUC rewards
long training. Long training destroys detection. So our own tuning pass was
steering away from the thing we actually measure, and its grid started at 25
epochs and only went up — the region that works, 12 to 18, was outside the
search entirely. The conclusion it reached was right. Its method was pointed
backwards, and we say so."

**Close on what got stronger, not weaker:** "The claim *the world model loses to
a gradient-boosted tree on real botnet traffic* now holds across six horizons,
five training lengths and up to six seeds — every configuration we tried.
Gradient boosting never dropped below 7 of 12; the world model never reached it.
Even allowed to pick its horizon knowing the test results, which nothing
deployable can do, it reaches 5 against 9. The upper bound loses. And the error
we corrected made us look **worse** than we were — we fixed it anyway, because a
number that flatters us would be a fault and so is this one."

**Backing:** `experiments/exp16_ctu13_horizon.py` (horizon sweep, oracle and
nested), `exp17_ctu13_seed_variance.py` (six seeds), `exp18_ctu13_epochs.py`
(training length).

### Q32. Explain the oracle run — you trained on the target?

**Say:** "Deliberately, as a diagnostic, and it is flagged in the file and
excluded from our prediction count. Two explanations remained — too little
signal, or something structural — and they call for opposite responses. Handing
the model a perfect noise-free target settles it: it still cannot represent a
conditional effect. That tells us to stop, which is worth more than another
month of tuning."

---

## Part 6 — deployment and operations

### Q33. Where does this sit in a real network?

**Say:** "On the low side of a data diode watching a critical enclave. It
receives a copy of traffic through the tap and has no route back — enforced by
the tests, not by policy. The console runs in the enclave and binds loopback by
default."

### Q34. What hardware does it need?

**Say:** "What we measured: a single process handles about 48,000 packets per
second, twelve shards reach 119,918, and the sensor holds 14,817 hosts in 2.58
MB. For a link faster than about 670 Mbps you need the kernel-fanout path we
have not built."

### Q35. What is the false-positive burden on an analyst?

**Say:** "At alpha 0.1 the calibration targets 90% coverage; we measured 90.8%
with 9.1% abstention and 99.5% accuracy on what it does answer. I would not
present that as a deployment false-positive rate — it is measured on this corpus
with its class balance, and a real network's benign traffic is more varied."

### Q36. Which diode vendor, and have you tested against one?

**Say:** "We have not. We model the constraint — one-way visibility, no reverse
channel — rather than a specific product, and the visibility profiles are the
abstraction. Testing against real diode hardware is exactly what we would want
from a deployment partner."

### Q37. What about encrypted traffic?

**Say:** "We never decrypt and we never look at payload. Everything is flow
metadata and timing. That is a constraint we adopted deliberately, and the
encrypted-C2 head is one of two we mark as handicapped because the signal it
would need — TLS client-fingerprint rarity — is not in flow records."

---

## Part 7 — weaknesses, asked and unasked

### Q38. What is the biggest weakness?

**Say:** "The packet-level pipeline has never run on real packets. Experiments
06 through 09 use generated packets, because CIC-IDS2017 ships flow records and
cannot exercise an assembler at all. The flow-level path is validated on real
data; the assembler and sharding are not."

### Q39. What would you do with six more months?

**Say:** "Three things in order. Real packet captures for the assembler path.
Kernel-level fanout for line rate. And for KALACHAKRA, a different formulation
of the counterfactual — we established that a difference of two rollout risks
collapses to an average effect, so another loss term is not the answer."

### Q40. What did you get wrong along the way?

**Say:** "Several things worth naming. We gave one condition features we
withheld from its baseline and produced a fake advantage — caught it, fixed it,
the advantage vanished. Our sharded pipeline silently lost 17% of rows to an
unordered shuffle. And our headline result turned out to be corpus-dependent,
which we found by attacking it ourselves."

**This question is a gift.** A team that can name three real bugs is a team that
was actually building.

### Q41. Why two problem statements? Isn't that unfocused?

**Say:** "They share a telemetry pipeline and a philosophy — measure what you
claim, and publish the refutations. One is detection under a visibility
constraint, the other is forecasting and intervention. The rules allow two, and
the second one is where we learned that a world model buys you an interventional
question rather than better detection."

### Q42. Who on the team did what?

**Prepare this properly.** A vague answer here reads as one person carrying the
project. Every member should be able to name a component they own and answer a
technical question about it. Assign ownership before the finale, not during it.

---

## Part 8 — questions worth asking the judges

Asking good questions signals confidence and buys information. Two or three,
not a list:

- "Is your interest more in the sensor being deployable in an enclave, or in the
  visibility-profile method transferring to other placements?"
- "Would you want the abstention rate tuned toward fewer misses or fewer
  handoffs? We can move that threshold, and it is a policy choice, not a
  technical one."
- "Is there a capture you would want this run against that we could not have
  known about?"

---

## Appendix — numbers you must be able to say without looking

| | |
|---|---|
| One-way tap, per-flow features only | 0.979 → 0.690 binary-F1 (exp04) |
| Same tap, with windowed host state | 0.981 — level with full visibility |
| Streaming vs exact batch | 14 of 16 features bitwise identical, 2.58 MB, 225,907 flows/s |
| Lateness budget | 15s recovers 12.35% of flows, changes F1 by 0.007 |
| Throughput | 119,918 pkt/s = 672 Mbps, against a 178,571 pkt/s target |
| Calibration | 90.8% coverage, 9.1% abstention, ECE 0.0007 |
| Evidence chain | 90,790 entries, verified in-browser and server-side |
| Low-rate attacks | host-window-alone 0.599 → 0.28 macro-F1; one-way tap result holds |
| KALACHAKRA counterfactual | says "isolate helps" in 94% of pairs vs 48% for an action-aware LSTM — but always-isolate scores 100% |
| KALACHAKRA lead time | LSTM 3.35 windows, world model 0.26 — we lose |
| KALACHAKRA on CTU-13 | world model 5 of 12, GBDT 7-9 of 12 — corrected upward from our own published 1 of 12 |
| Pre-registered predictions | 82 total, 33 refuted |
| Tests | 288 (EKAGRA) + 100 (KALACHAKRA) = 388 |

**Last thing.** If a judge tells you a number is wrong, do not argue from
memory — open the repository and look. Being seen to check is worth more than
being seen to be certain.
