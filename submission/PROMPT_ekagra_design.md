# Design brief — EKAGRA deck (SIH 2026, PS ID SIH26145)

You are improving the visual design of a **Smart India Hackathon 2026 idea
submission**. The file is `SIH2026_SIH26145_EKAGRA_idea.pptx`. It is 6 slides,
16:9, 13.33 × 7.5 inches.

**Your job is visual only.** The content is finished, factually verified, and
every number is reproducible from a code repository. Treat the words and figures
as fixed copy. Your task is to make it *land in two minutes*.

---

## How this deck is actually scored — design for this, not for beauty

SIH evaluators spend **2–3 minutes per submission**. The official weighting:

| criterion | weight | what carries it on this deck |
|---|---|---|
| **Innovation & uniqueness** | **25%** | the comparison grid on slide 2 |
| Problem understanding & clarity | 20% | slide 2 headline + the 0.69→0.98 chart |
| Technical feasibility | 20% | slide 3 architecture diagram |
| Impact & scalability | 20% | slide 5 numbers |
| Presentation quality | 15% | everything you are about to do |

Two consequences you must design around:

1. **The comparison grid on slide 2 is the single highest-value object in the
   deck.** It is the only thing answering "why is this different from what
   already exists". Give it the most attention after the title hierarchy.
2. **Diagrams beat text, always.** The official template's own instruction slide
   says: *"Try to avoid paragraphs and post your idea in points / diagrams /
   Infographics / pictures."* Where you can turn a sentence into a labelled
   visual without losing a number, do it.

---

## What this project is

EKAGRA is a network-threat sensor for a **data diode** — a one-way link into a
secure enclave. The sensor sees traffic crossing the link but has **no path
back**: it cannot query a threat-intelligence service, probe a host, or block
anything. The argument is that conventional intrusion detectors are trained on
two-way visibility they will not have there, and that the fix is not a better
classifier but a sensor that keeps per-host state.

The client is India's **National Technical Research Organisation**. Theme:
Blockchain & Cybersecurity. Category: Software. Team: **AlgoRhythms**.

This deck deliberately publishes results that make the team look worse, because
that is its central argument. Those are on **slide 4**, where the official
template asks for risks and challenges. Do not move them forward and do not
soften them.

**Palette (already applied — keep it):**

| role | hex |
|---|---|
| primary | `#0B6B63` deep teal |
| warning / refutation | `#A3341F` rust |
| ink | `#141918` |
| muted | `#55605D` |
| pale ground | `#F4F7F6` |

---

## Hard constraints — breaking any of these can disqualify the submission

1. **Exactly 6 slides.** The official template's instruction slide says
   *"maximum slides limit up to six (6), including the title slide"*. Do not
   add, remove, split or reorder.
2. **Do not change the slide titles.** They are the template's prescribed
   sections: title page, `IDEA TITLE`, `TECHNICAL APPROACH`,
   `FEASIBILITY AND VIABILITY`, `IMPACT AND BENEFITS`,
   `RESEARCH AND REFERENCES`. Judges score against these headings.
3. **Do not alter, round, soften or delete any number, claim or caveat.**
   **Protected values — every one must survive verbatim:**

   | value | where | why it must not be "improved" |
   |---|---|---|
   | the four comparison rows (Suricata/Zeek, Darktrace/Vectra, Owl/Waterfall, EKAGRA) | slide 2 | **the 25% criterion** — never compress to prose |
   | `0.6903` vs `0.9810` two-bar chart | slide 2 | the core capability claim |
   | `0.9810`, `Rs 0 / year`, `672 Mbps`, `17 / 42` | slide 2 stat cards | |
   | `Rs 13-37 lakh` licence avoided | slide 2 card, slide 5 | the economic impact figure |
   | `877,801 flows` | slide 2 | corpus size |
   | `0.9812` four-bar ablation | slide 4 | the team's own control, which **refuted their headline** |
   | "not the 1 Gbps we first claimed" | slide 2 card, slide 4 | a retracted claim, stated as retracted |
   | "we called QUIC a hard ceiling - we were wrong" | slide 4 | a **self-correction**, deliberately on the slide |
   | `80,291 to 32,069` UDP vs TCP on 443 | slide 4 | scale of the QUIC problem |
   | `29.44 lakh` CERT-In incidents, `up 85%` | slide 5 | the national scale figure |
   | `0` outbound connections | slide 5 | the architectural guarantee |

   If text must shrink to fit, cut connective words — never a figure, never a
   qualifier, never a retraction.
4. **Keep the template's own furniture**: the SIH logo (top-right, slide 1), the
   grey footer bar, slide numbers, and the oval reading **AlgoRhythms** on
   slides 2–6.
5. **Nothing below y = 6.95 inches** — that is where the footer bar begins.
   Minimum 0.5 inch margins elsewhere.
6. Body text never below **10 pt**. (The official guidance says 14 pt minimum
   for body copy; our dense grids run smaller by necessity — do not go lower
   than 10 anywhere, and prefer 11+ wherever space allows.)
7. **Export a PDF alongside the .pptx.** The SIH portal accepts **PDF only** —
   no PPT, no Word, no other format.

---

## Slide-by-slide direction

### Slide 1 — Title page
Leave the structure. Improve typographic hierarchy on the Problem Statement ID /
title / organisation / theme / category / team block. Restrained: this is a
national-security submission, not a product launch.

### Slide 2 — `EKAGRA — detection that survives a one-way tap`
**The slide that wins or loses the deck. Most of your effort goes here.**

Its layout is: one-line solution statement → comparison grid (left) + native bar
chart (right) → four stat cards → one-line uniqueness statement.

- **The comparison grid is the point of the slide.** Four rows, three columns
  (Approach / What it requires / Why it fails behind a diode), with the EKAGRA
  row filled and bold. Make it read as a table a judge can scan in ten seconds:
  strong header, clear column rhythm, generous row height, the final row
  visually distinct. **Do not turn it into paragraphs.** If you improve one
  object on this deck, improve this one.
- **Keep the bar chart native** (it is a real PowerPoint chart). Two bars,
  `0.6903` for a conventional IDS put behind the tap and `0.9810` for EKAGRA.
  The failing bar is rust on purpose. Restyle freely — bar thickness, rounded
  ends, label placement, gridline removal — but do not change the values,
  the category names, or which bar is red.
- Four stat cards: `0.9810`, `Rs 0 / year`, `672 Mbps`, `17 / 42`. Make the big
  numbers confident and the captions quieter. Keep all three lines of each card.
  Note `Rs 0 / year` is a phrase, not a digit — size it so it still reads.
- Consider rendering `Rs` as the rupee sign **₹** if your font stack supports it
  cleanly. If there is any doubt it will render on another machine, leave `Rs`.

### Slide 3 — `TECHNICAL APPROACH`
Currently a 5-stage pipeline of boxes: **Packets → Flow assembler → Streaming
host-window → Detector heads → Calibration + evidence**, with the middle two
emphasised in teal, plus two blocks of supporting detail.

**This slide carries the 20% technical-feasibility score and is the weakest
visual in the deck. Rebuild it as a real architecture diagram.**

- Give every stage a flat line **icon** above it: packet/wave, funnel, sliding
  window or clock, shield or radar, seal or lock.
- **The chevrons between stages are the literal character `>`. Replace them with
  real arrow shapes.**
- Keep the caption "One-way data flow. No component downstream of ingest can
  call anything upstream." — it is the architectural claim of the whole project.
  Reinforce it with a **single bold directional arrow spanning the entire
  pipeline**, and consider a struck-through or barred return arrow underneath to
  show the path that does not exist. That one visual states the entire premise.
- The supporting text mentions specific mechanisms — flow timeouts (idle 15 s /
  active 120 s), HyperLogLog / Count-Min / Misra-Gries sketches, a 60 s window
  with a 15 s lateness budget, JA4 fingerprinting, QUIC Initial decryption.
  These are the correct technical terms and must stay. If you can hang them off
  the diagram as small labelled callouts rather than leaving them in a text
  block, the slide gets substantially stronger.

### Slide 4 — `FEASIBILITY AND VIABILITY`
Left half: the four-bar ablation chart (`0.9812 / 0.9810 / 0.6903 / 0.9793`)
with the **control highlighted in rust**, plus the caption explaining that the
team's own control narrowed their headline. Right half: three risk cards —
Throughput, Corpus, Encrypted web.

- **Keep the ablation chart native and keep the rust bar.** That bar is the
  team's own control showing 16 host-window features alone match full
  visibility. If anything, make it read *more* clearly as "this is the
  uncomfortable one".
- Give the three risk cards a small icon each: speedometer, database,
  padlock-with-a-crack.
- The third card is a **self-correction** — the team says a limit they published
  was wrong and then removed it. Let it read confident, not apologetic.

### Slide 5 — `IMPACT AND BENEFITS`
Three impact stat cards across the top (`Rs 13-37 lakh`, `29.44 lakh`, `0`),
then a 2 × 2 grid of benefit cards.

- Give each of the four cards an icon in a tinted circle.
- The top three numbers are the quantified-impact evidence a judge scores on.
  Give them real weight — this is the slide where scale gets proven.
- Card four ("Transferable — one core, two problem statements") mentions SDG 9
  and SDG 16. If you can add the two official SDG colour tiles small and clean,
  do; if it would look like clip-art, leave it as text.

### Slide 6 — `RESEARCH AND REFERENCES`
Academic citations, datasets, and scale sources. Keep it plain and readable; a
reference slide should look like references. Improve leading and hanging
indents. Do not drop any citation.

---

## Style

- **Restrained and technical.** An instrument panel, not a startup pitch.
- Icons: flat, single-weight line icons in one palette colour. **No clip-art, no
  3-D, no stock photos, and absolutely no hooded-figure or
  padlock-on-green-binary cybersecurity clichés.**
- Subtle depth is welcome: soft shadows, light tints, generous whitespace.
- **Do not add** decorative colour bars, edge stripes, or accent lines under
  titles. Those read as AI-generated filler.
- Do not centre body text. Left-align paragraphs, lists and table cells; centre
  only titles and the stat cards.
- Keep the file **under 10 MB**.

---

## Before you return the file

- [ ] Still exactly 6 slides, section titles unchanged
- [ ] No text overflows its shape or the slide edge
- [ ] Nothing overlaps the footer bar (y > 6.95")
- [ ] The slide-2 comparison grid is still a **grid**, still four rows, with the
      EKAGRA row visually distinct
- [ ] Both bar charts are still **native** charts with the same values, and the
      rust bars are still rust (slide 2: the failing IDS; slide 4: the control)
- [ ] **Every value in the protected table above is present and identical**,
      including both self-corrections
- [ ] Slide 3 has real arrows, not `>` characters, and a spanning one-way arrow
- [ ] Team oval still reads **AlgoRhythms** on slides 2–6
- [ ] Body text ≥ 10 pt everywhere
- [ ] **Exported a PDF** — the SIH portal accepts nothing else
