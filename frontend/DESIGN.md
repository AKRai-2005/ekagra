# EKAGRA console — design audit and design system

This file records why the console looks the way it does. Read it before changing
the visual design, so a change is an argument with a reason rather than a drift
back towards a generic dashboard.

## How the audit was done

Evidence, not impressions. The console was driven through its real states — load,
select, verify, tamper, reset, filter, replay, Findings — with Playwright against
the live API at 1440×900, 834×1112 and 390×844. Contrast ratios, font sizes,
radii and colour literals were computed from the source, not estimated.

## The 30-point audit

Priority: **C** critical · **H** high · **M** medium · **L** low · **—** not present.

| # | Dimension | Found | Where, and why it hurts | Change | P |
|---|---|---|---|---|---|
| 1 | Generic layout | Partly | The two-pane master/detail layout is right for this task. The header's six equal KPI tiles are the stock dashboard composition and say nothing about how the numbers relate. | Keep the two panes. Group the readouts by meaning: sensor, chain, calibration. | M |
| 2 | Identical cards | **Yes** | Every one of the 400 alerts was a bordered, rounded, filled box with a gap under it. ~70px per alert, so ~10 visible at 1440×900. A log is read down columns; boxes isolate rows and defeat column scanning. | Ruled ledger rows on one line, 40px each. Roughly double the rows per screen. | H |
| 3 | Rounded corners | Minor | Radii were small and fine for an instrument. The fault was four different values (2, 3, 4, 5px) chosen per component. | Two radii: 2px for markers, 4px for controls and surfaces. | L |
| 4 | Spacing | **Yes** | ~19 distinct padding/gap/margin values (3, 5, 7, 9, 11, 13, 15px…). No rhythm, so nothing lines up across sections. | A 4px scale: 4, 8, 12, 16, 24, 32. | M |
| 5 | Visual hierarchy | **Yes** | Six section headings in one identical style (11px, uppercase, tracked, grey). The accent teal marked seven unrelated things — the LIVE badge, the active tab, Verify, the selected row, hashes, head names, links — so it signalled nothing. | Sentence-case headings at readable size. Teal reserved for integrity and the primary action only. | H |
| 6 | Typography | Partly | System fonts are the correct choice for an air-gapped enclave (no web fonts to fetch). But IP addresses were set in a proportional face, so they misaligned row to row, and percentages had no tabular figures. | All data — IPs, IDs, sequence numbers, hashes, percentages — in the monospace with tabular numerals. Prose stays in the sans. | M |
| 7 | Font sizes/weights | **Yes**, inverted | Not too large — too *many*: 13 sizes in half-pixel steps (9.5, 10, 10.5, 11, 11.5, 12, 12.5, 13, 13.5, 14.5, 15, 15.5, 17). | Five steps, later raised one step for legibility: 12, 13, 14, 16, 20. | M |
| 8 | Generic palette | Partly | Teal-on-dark is common, but it matches the EKAGRA deck, so it stays. The problem was use: seven filled rainbow pills for threat classes (purple DGA, blue scan, green encrypted…) where colour carried no meaning. | Colour means state only: teal = integrity holds, rust = integrity broken / critical, amber = uncertainty. Threat class is a text code. | M |
| 9 | Gradients | — | None present. None added. | — | — |
| 10 | Shadows | — | None present. None added. | — | — |
| 11 | Contrast | **Yes** | `--ink3` carried alert IDs, sequence numbers, every label and every heading, and failed WCAG AA everywhere it sat: **4.26** on the page, **3.94** on rows, **3.62** on the selected row (4.5 required). On a projector this text disappears. | Re-derived with the lighter theme: `#A0ADA9`, worst case 5.0:1. Every token passes AA on every surface. | **C** |
| 12 | Alignment | **Yes** | Rows split content to the two edges with a void in the middle; host, ID and severity stacked in varying heights (DDOS rows 72px, ABSTAIN rows 54px), so the list had a ragged rhythm. At tablet width the rows were ~1,400px wide with content pinned to both ends. | Fixed columns on a grid: sequence, class, host, alert ID, severity, confidence. Every row the same height. | H |
| 13 | Whitespace | Both | Rows too loose (three short facts in 70px). The detail pane over-crowded: an 11px explanatory paragraph wrapped inside a key–value cell. | Tighter rows. Explanatory notes moved out of value cells into proper notes under their section. | M |
| 14 | Generic icons | — | Effectively no icons, and none needed. | Added one mark — see #28. | — |
| 15 | Decoration | Minimal | The dashed border on ABSTAIN is semantic (dashed = uncertain), not decorative. Kept; the offline status says the same with a hollow dot. | Keep. | — |
| 16 | Repetitive sections | **Yes** | The evidence pane was four identical bordered panels with identical uppercase titles. | One continuous document separated by space and hairlines. No boxes inside the column. | M |
| 17 | Predictable hero | — | It is a console; there is no hero. | — | — |
| 18 | Calls to action | **Yes** | Verify, Tamper and Reset sat side by side in three unrelated styles. Tamper — a *demonstration* control — was as loud as Verify, the real operation. Nothing said which was which. | Verify is the one solid primary button. Tamper and Reset are grouped and labelled as a simulation. Labels unchanged. | H |
| 19 | Unnecessary animation | — | One animation: new rows sliding in during replay. It shows arrival, and it respects reduced motion. Kept. | Shortened 450 → 240ms. | — |
| 20 | Animation timing | Minor | No transitions at all on hover or selection, so state changes snapped. | One timing token, 120ms, for hover and selection. | L |
| 21 | Interaction states | **Yes** | Hover, selected and broken all changed the same border, so a selected *broken* row could not show both states. | Separate channels: hover and selection change the background; integrity state lives on the chain rail. | M |
| 22 | Component consistency | **Yes** | Three unrelated button styles; mode badges using colours outside the token set; confidence shown as 100.0% in the list and 100.00% in the detail. | One button system, one badge system, one number format. | M |
| 23 | Borders and dividers | **Yes** | Boxes inside boxes: bordered rows in a bordered column; bordered panels in a bordered column; bordered tables in bordered panels; a bordered verdict with a divider inside it. | Hairline rules only where they separate rows or sections. | H |
| 24 | Images | Partly | Findings placed white matplotlib charts directly on the dark page at 1,180px — a glaring rectangle butted against a hard border. Separately, Figure 1's legend overlaps its bars, but that is baked into the PNG by `backend/experiments/make_figures.py`. | Figures sit on a light mat, framed as exhibits, width capped for reading. The legend overlap was then fixed in the backend script — see below. | M |
| 25 | Responsive | **Yes** | Below 900px the list and evidence stack. Tapping an alert updated a panel **29,545px below on tablet (27 screens) and 29,606px below on a phone (35 screens)**, and the page did not scroll. Verify and Tamper were down there too — the core demonstration was unreachable on a phone. | The list becomes a bounded, scrollable ledger on narrow screens, the evidence follows it directly, and selecting an alert scrolls the evidence into view. | **C** |
| 26 | Navigation | Minor | The active tab was a filled pill and the other plain text — it read as a button beside a link, not as a tab set. | Underline tabs on the header's bottom edge. | L |
| 27 | Content structure | Partly | The detail pane mixed the assessment, a long caveat and the chain of custody in one list; the HMAC caveat was easy to miss. | Three labelled sections — assessment, chain of custody, reasoning — each with its caveat directly beneath it. | M |
| 28 | Visual identity | **Yes** | No mark, no favicon (the tab showed a blank icon and every load logged a **404** for `favicon.ico`), nothing tying the console to the EKAGRA deck and report. | An original mark — see *The logo* below — as logo and favicon. Palette aligned with the deck's teal and rust. | M |
| 29 | Small details | **Yes** | "1 flows"; 100.0% vs 100.00%; hashes coloured like links though not clickable; 8 inline `style=` attributes; 21 hard-coded colours outside the token set. | Pluralisation, one format, hashes in neutral ink, styles moved into classes, colours into tokens. | M |
| 30 | Cohesion | Partly | Two visual languages: boxed cards in the stream, a spreadsheet in the feature table, a different treatment again in Findings. | One ledger language across the stream, the evidence and the detector heads. | M |

**Not present, stated so they are not "fixed":** gradients, shadows, a hero
section, decorative illustration, gratuitous animation.

## Design direction: the ledger

**Personality.** A forensic instrument, not a SaaS dashboard. What this console
proves is that a chain of evidence has not been altered, so it borrows the
language of the thing it verifies: a numbered, ruled, append-only ledger. Sober,
dense, exact, legible on a projector and across a long shift.

**The one distinctive element — the chain rail.** A thin vertical line runs down
the sequence column and joins every row: the hash chain, drawn. Before
verification it is neutral. After verification each link turns teal if it holds
and rust where the verifier found a break. It is not decoration: it displays the
verifier's per-link result, so tampering is visible in the list itself, at the
row where it happened, not only in a message box.

**Colour** — meaning only.

| Token | Value | Meaning |
|---|---|---|
| `--teal` | `#5FD2C2` | integrity holds · live · primary action |
| `--rust` | `#F08F79` | integrity broken · critical |
| `--amber` | `#E2BA62` | uncertainty — abstain, offline |
| `--ink` / `--ink2` / `--ink3` | `#F0F4F3` / `#C3CDCA` / `#A0ADA9` | text, three levels, all AA |
| `--bg` / `--surface` / `--raised` | `#1B2323` / `#222B2B` / `#2A3434` | three depths, no more |

A dimmed dark theme — 2.7× the luminance of the first, near-black version, so it
survives a projector. Every text token clears WCAG AA on every surface it sits
on (worst case 5.0:1); control borders reach 3.5:1, the non-text threshold.

Threat class is a text code, not a colour. Severity keeps its existing
width-plus-colour bar (width is there for colour-blind users) on a neutral-to-warm
ramp.

**Type.** System sans (Segoe UI Variable) for prose and controls; system
monospace (Cascadia Mono) with tabular numerals for every datum. Scale:
12 / 13 / 14 / 16 / 20px. Both faces are variable fonts, so weight is set in
between the usual steps — 420 for body, 450 for data, 550 for host addresses
and readouts — which thickens strokes for legibility without shouting in bold.
Uppercase only for fixed codes (DDOS, ABSTAIN), never for headings.

**The logo.** Three strokes converging on one point. EKAGRA is *eka* + *agra*,
"one-pointed": several streams, one point of attention, flowing one way — which
is also what the sensor is. Drawn from scratch because at least four companies
already trade as Ekagra; any borrowed mark would be someone else's trademark.
Chosen over a focal-ring (reads as a stock target or radio button at 16px) and
an E-monogram (reads as a play button at 16px). Inline SVG, so the air-gapped
enclave never fetches it.

**Status.** A fully rounded pill with a dot, in sentence case: *Live*,
*Offline snapshot*, *No data*. The offline dot is hollow, so the shape and not
only the colour says "not live". The dot does not pulse: live here means the
console reads the API, not that alerts are streaming in.

**Space.** 4px base: 4, 8, 12, 16, 24, 32. Radii 2px and 4px.

**Components.** One button system (primary, secondary, quiet). One badge system.
Rows are ruled, never boxed. Surfaces are separated by rules and space, never
nested boxes.

**Motion.** 120ms for hover and selection. 240ms for a replayed row arriving.
Nothing moves that does not carry information. Reduced-motion removes all of it,
including the scroll to evidence.

**Responsive.** Two panes above 900px. Below it the list becomes a bounded
ledger with the evidence directly after it, and selection scrolls the evidence
into view. Below 700px the readouts become one horizontal strip and ledger rows
wrap to two lines, keeping sequence and confidence aligned.

## Deliberately not changed

- Every function, API call, validation rule and ARIA attribute.
- Every button and tab label — the presentation and video scripts quote them.
- System fonts: the enclave has no route to a font server.
- The severity bar's width encoding: an accessibility decision, not a style.

## Found and fixed after the redesign

- **Figure 1 overlaps — fixed.** Panel 2's legend sat inside the ddos and beacon
  bars; it is now one row above them, the pattern `make_figures_pipeline.py`
  already used. Panel 1's arrow landed on the "7" of its 0.711 label. Both fixed
  in `backend/experiments/make_figures.py`, which only reads
  `results/exp01_ablation.csv` — the data is unchanged, only the layout moved.
- **Stale console after an update — fixed.** `index.html` and `data.js` had an
  ETag but no `Cache-Control`, so browsers cached them heuristically for days.
  Now `no-cache`, and an unchanged file answers `304` with no body (it re-sent
  48 KB and 503 KB on every load until that was added). Both pinned by tests.
- **Numbers rendered differently per machine — fixed.** Bare `toLocaleString()`
  printed "4,71,631" on an en-IN machine and "471,631" elsewhere. All counts go
  through one `num()` pinned to `en-US`, matching the deck and report.
- **Safari logged an error when opened from disk — fixed.** The page probed for
  an API on `file://`, where there cannot be one. It now goes straight to the
  snapshot.

## Verified

Chromium, Firefox 153 and WebKit 26.5, each live and offline (`file://`), plus
WebKit emulating an iPhone 13 with touch input: select, verify, tamper, reset,
filters, Findings, Replay over SSE, and no horizontal scroll. Number formatting
checked under `en-IN`, `en-US` and `de-DE` in all three engines.

## Not verifiable from here

- **A physical phone or iPad.** Emulation covers layout, touch events and the
  WebKit engine; it does not cover real iOS Safari chrome, the on-screen
  keyboard, or a real device's GPU. The server binds 127.0.0.1 on purpose, so a
  phone cannot reach it without `python demo.py --host 0.0.0.0` — which exposes
  an unauthenticated console to the local network. Use a trusted network only.
