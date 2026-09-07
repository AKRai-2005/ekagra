# EKAGRA — frontend

The analyst-facing console for SIH26145. One file, `index.html`, with no build
step, no framework and no CDN.

## Run it

From the project root:

```bash
cd ekagra/backend && python demo.py
```

That starts the read-only API on `http://127.0.0.1:8000` and serves this folder.
Edit `index.html`, refresh the browser — there is nothing to rebuild.

It also works with no server at all: open `index.html` directly and it falls
back to the `data.js` snapshot. You lose the Findings tab and the replay, which
need the API.

## Why there is no framework

The deployment this is built for is an air-gapped monitoring enclave with no
route to the internet. A CDN `<script>` tag would fail there, and a build step
means the thing running in the enclave is not the thing in the repository. If
you add a dependency, vendor it into this folder — do not fetch it at runtime.

## The API contract

Everything is `GET`. There are no write endpoints and there never will be — a
test in the backend fails the build if one appears.

| endpoint | returns |
|---|---|
| `GET /api/health` | `{status, entries, log}` |
| `GET /api/summary` | counts, by-class breakdown, chain head, model hash |
| `GET /api/alerts?limit=&offset=&threat_class=&decision=` | `{total, offset, limit, alerts[]}` — **no `features` field**, it is too large for a list |
| `GET /api/alerts/{seq}` | one alert **with** `features` |
| `GET /api/verify` | `{verified, problems[], entries, head}` |
| `GET /api/heads` | the six detector heads with rationale and known gaps |
| `GET /api/figures` | `[{file, title, claim}]` |
| `GET /figures/{file}` | one PNG, allowlisted against the manifest |
| `GET /events?start=&limit=` | SSE replay, `event: alert` then `event: end` |
| `GET /data.js` | sensor run metadata (packets, throughput, calibration) |

An alert looks like this:

```json
{ "seq": 90390, "alert_id": "EK-00059-4625", "ts": 3540.0, "window": 59,
  "host": "105.35.144.90", "threat_class": "ddos", "score": 0.99,
  "confidence": 0.99, "decision": "ALERT", "model_hash": "...",
  "feature_hash": "...", "prev_hash": "...", "entry_hash": "...",
  "hmac": "...", "observed": {...}, "decision_path": [...] }
```

`decision` is `ALERT` or `ABSTAIN`. Abstention is not an error — it is the
model declining to name a class, and it should stay visually distinct.

## Three things not to break

**1. `normalise()` — validation at the boundary.** Every bundle passes through
it before reaching the DOM. It exists because this console *was* injectable:
`threat_class` was concatenated into a class attribute, and a crafted log could
close the attribute and add an event handler. If you add a field to the render
path, escape it with `esc()` or validate it in `normalise()`.
`backend/tests/test_console_injection.py` fails the build if an interpolation
in the render path is neither escaped nor a validated token.

**2. `SEP` and `canonical()` must match the backend byte for byte.** The chain
verification re-derives every hash here in the browser, which is the whole
point - a verifier that trusts the producer verifies nothing. `SEP` is the
US separator U+001F (written as a `\u001f` escape in the source), field order is
fixed, and floats use six decimal places. If any of that drifts from
`backend/src/ekagra/evidence/bundle.py`, the console will report tampering
that never happened.

**3. Do not re-render the whole list per event.** The SSE replay pushes 400
alerts; rebuilding the list each time is quadratic and froze the page for
eight seconds. `appendRow()` adds one row, and one delegated click listener
serves all of them.

## Where the design has room

These are genuine gaps, not a wish list:

- **Severity now ships** (`backend/src/ekagra/detect/severity.py`) as a second
  axis beside confidence, never multiplied into it: confidence is "am I sure?",
  severity is "how bad if I am right?", and an analyst triages on both. The rail
  encodes the band by **width as well as colour**, so it does not fail for
  colour-blind users — keep that if you restyle it. Abstained alerts show no
  severity in the list on purpose: severity is derived from the threat class,
  and an abstention does not assert one.
- **No filtering by host or time range**, only by class and decision.
- **The evidence panel is dense.** It is correct and not especially readable.
- **No empty-state illustration**, no loading skeleton — just text.
- **Colour is the only channel** distinguishing threat classes. That fails for
  colour-blind users; the tag text carries the same information, but shape or
  iconography would be better.

## Accessibility, already done — please keep it

Alert rows are `role="button"` with `tabindex="0"`, Enter/Space select and
arrow keys move between them. The verify verdict is an `aria-live` region so a
screen reader hears the result change. Tabs use a roving tabindex. Touch
targets are 44px under `pointer: coarse`. There is a skip link.
