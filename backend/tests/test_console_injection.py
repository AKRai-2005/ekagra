"""The console must not execute what the evidence log contains.

Why this test exists
--------------------
This console's entire claim is that the evidence log has not been altered since
it was written. The log is therefore precisely what an attacker with a foothold
on the sensor would tamper with - so rendering its contents into the DOM without
validating them argues against the product's own premise.

It was also concretely exploitable. `threat_class` was concatenated into a class
attribute:

    const cls = "t-" + b.threat_class;
    `<span class="tag ${cls}">`

and a value of `x" onmouseover="..."` closed the attribute and added an event
handler.

What these tests do, and what they cannot
-----------------------------------------
They are **source and fixture guards**, not a browser run. They build a log
carrying six payloads, and they assert three properties of the console source:
that a boundary validator exists, that the class attribute is fed the validated
token rather than the raw field, and that every interpolation in the render path
ends in `esc()`, a validated token, or a numeric coercion.

They deliberately do **not** grep the rendered HTML for payload strings. A
string check cannot distinguish `<img onerror=...>` from the escaped text
`&lt;img onerror=...&gt;` - one is an element, the other is four words - and an
earlier version of this file reported three false failures for exactly that
reason.

Proving nothing executes needs a real DOM. That check was run manually against
this log through the live API (`document.querySelectorAll` for injected
elements and `on*` attributes); automating it would need a headless browser,
which this project does not depend on and which is not worth the dependency for
one test. The guards above are what keeps a future edit from reopening the hole.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from ekagra.evidence.bundle import EvidenceLog

ROOT = Path(__file__).resolve().parents[1]
CONSOLE = ROOT.parent / "frontend" / "index.html"

# Each payload is a real escape technique, placed in a field the console renders.
PAYLOADS = {
    "attribute_breakout": 'x" onmouseover="__PWNED__()" data-x="',
    "script_tag": "<script>__PWNED__()</script>",
    "img_onerror": "<img src=x onerror=__PWNED__()>",
    "svg_onload": "<svg onload=__PWNED__()>",
    "quote_in_id": '1" onclick="__PWNED__()',
    "closing_span": '</span><span onmouseenter="__PWNED__()">',
}


@pytest.fixture(scope="module")
def hostile_log(tmp_path_factory) -> Path:
    """An evidence log whose fields carry markup, with a valid hash chain.

    The chain is genuine: we are testing rendering, not verification, so the
    console must accept these entries as intact and still refuse to execute
    them.
    """
    path = tmp_path_factory.mktemp("hostile") / "evidence.jsonl"
    log = EvidenceLog(key=b"", model_hash="a" * 64)
    for i, (name, payload) in enumerate(PAYLOADS.items()):
        log.append(
            alert_id=payload if name == "img_onerror" else f"EK-{i:05d}",
            ts=float(i),
            window=i,
            host=payload if name in ("script_tag", "svg_onload") else f"10.0.0.{i}",
            threat_class=payload if name == "attribute_breakout" else "ddos",
            score=0.9,
            confidence=0.9,
            decision="ALERT",
            features={"hw_src_n_flows": 1.0},
            observed={
                "true_label": payload if name == "closing_span" else "ddos",
                # observed is a free-form dict rendered into the detail panel,
                # so it is a rendering sink like any other.
                "flows_in_window": payload if name == "quote_in_id" else 3,
                "peers": 2,
            },
            decision_path=[payload if name == "quote_in_id" else "conformal"],
        )
    path.write_text(
        "\n".join(json.dumps(b.to_dict()) for b in log.bundles) + "\n",
        encoding="utf-8")
    return path


def test_the_payloads_really_are_in_the_log(hostile_log):
    """Guard against the test passing because the fixture wrote nothing."""
    raw = hostile_log.read_text(encoding="utf-8")
    assert "__PWNED__" in raw
    assert raw.count("__PWNED__") >= len(PAYLOADS)


def test_console_validates_before_rendering(hostile_log):
    """The console source must normalise bundles rather than trust them."""
    src = CONSOLE.read_text(encoding="utf-8")
    assert "function normalise(" in src, "no boundary validation in the console"
    # The class attribute must be fed the validated token, never the raw field.
    assert '"t-" + b.css_class' in src
    assert '"t-" + b.threat_class' not in src, \
        "raw threat_class is still reaching a class attribute"
    # esc() must cover quotes, or attribute contexts stay open.
    esc_body = re.search(r"function esc\(s\)\{(.*?)\n\}", src, re.S).group(1)
    for ch in ("<", ">", "&", '"', "'"):
        assert ch in esc_body, f"esc() does not handle {ch!r}"


def test_every_rendered_field_is_escaped_or_validated():
    """No interpolation of log data may reach the DOM raw.

    Walks the render functions and requires each `${...}` to be either esc()'d,
    a validated token, an internally-built string, or arithmetic.
    """
    src = CONSOLE.read_text(encoding="utf-8")
    js = re.search(r"<script>(.*?)</script>", src, re.S).group(1)
    render = js[js.index("function rowHTML("):js.index("/* ---------------------------------------------------------------- replay */")]

    # The screen-reader label is assembled from raw fields and then escaped once
    # at its single sink. Escaping the parts as well would double-encode, so the
    # rule for that string is checked separately, below, rather than loosened.
    assert 'aria-label="${esc(label)}"' in render, "aria-label is not escaped"
    assert not re.search(r'aria-label="\$\{label\}"', render)
    label_stmt = re.search(r"  const label = .*?;\n", render, re.S)
    assert label_stmt, "label construction not found - has rowHTML changed?"
    render = render.replace(label_stmt.group(0), "")

    offenders = []
    for m in re.finditer(r"\$\{([^{}]+)\}", render):
        e = m.group(1).strip()
        ok = ("esc(" in e or ".map(esc)" in e          # escaped at the sink
              or e.startswith("(100*b.confidence)")     # arithmetic on a number
              or e == "b.severity_score.toFixed(2)"      # n_()-normalised, digits only
              or e.startswith("Number(")                # coerced to a number
              or e in ("cls",                            # validated token
                       "selected===b.seq",                 # a boolean
                       'fresh===b.seq?"fresh":""',
                       'selected===b.seq?"sel":""',
                       'broken.has(b.seq)?"broken":""')
              or e.startswith("feats.length"))
        if not ok:
            offenders.append(e[:60])
    assert not offenders, "unescaped interpolations in render path: " + "; ".join(offenders)
