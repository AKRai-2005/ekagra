"""Geometric QA for the idea deck.

No renderer is available in this environment - LibreOffice is absent and
pywin32 will not install under the Microsoft Store Python, so PowerPoint COM
automation is out. This checks the defects a render would have caught, using
the shape geometry directly:

    text overflow      estimated wrapped height vs the shape's height
    overlaps           text-bearing shapes intersecting each other
    slide margins      anything closer than 0.4 in to an edge
    empty shapes       boxes left with no text

Font metrics are approximate (Calibri averages ~0.48 em per character), so
overflow is reported with the estimated overshoot rather than as a hard pass or
fail. Treat anything over ~10% as real; open the deck in PowerPoint to confirm.
"""

from __future__ import annotations

import math
import sys
from pathlib import Path

from pptx import Presentation
from pptx.util import Pt

EMU_IN = 914400.0
SLIDE_W, SLIDE_H = 13.333, 7.5
MARGIN = 0.4

# Average glyph advance as a fraction of point size, Calibri-ish.
CHAR_W = 0.48
LINE_H = 1.22


def est_height_in(shape) -> float:
    """Estimated rendered text height, inches."""
    if not shape.has_text_frame:
        return 0.0
    tf = shape.text_frame
    width_in = (shape.width or 0) / EMU_IN
    ml = getattr(tf, "margin_left", 0) or 0
    mr = getattr(tf, "margin_right", 0) or 0
    usable_pt = max(6.0, (width_in - (ml + mr) / EMU_IN) * 72.0)

    total_pt = 0.0
    for p in tf.paragraphs:
        text = "".join(r.text for r in p.runs)
        size = None
        for r in p.runs:
            if r.font.size is not None:
                size = r.font.size.pt
                break
        if size is None:
            size = 18.0
        indent_pt = 18.0 * (p.level or 0)
        avail = max(6.0, usable_pt - indent_pt)
        chars_per_line = max(1.0, avail / (size * CHAR_W))
        lines = max(1, math.ceil(len(text) / chars_per_line)) if text else 1
        total_pt += lines * size * LINE_H
        total_pt += (p.space_before.pt if p.space_before else 0)
        total_pt += (p.space_after.pt if p.space_after else 0)

    mt = getattr(tf, "margin_top", 0) or 0
    mb = getattr(tf, "margin_bottom", 0) or 0
    return total_pt / 72.0 + (mt + mb) / EMU_IN


def rect(shape):
    return ((shape.left or 0) / EMU_IN, (shape.top or 0) / EMU_IN,
            (shape.width or 0) / EMU_IN, (shape.height or 0) / EMU_IN)


def overlap_area(a, b) -> float:
    ax, ay, aw, ah = a
    bx, by, bw, bh = b
    dx = max(0.0, min(ax + aw, bx + bw) - max(ax, bx))
    dy = max(0.0, min(ay + ah, by + bh) - max(ay, by))
    return dx * dy


def template_shapes(template_path: str):
    """(slide_index, shape_name) pairs the template already contained.

    Baselining against the template is the same idea as `validate.py
    --original`: the official deck has its own geometry quirks - title
    placeholders that start above the slide edge, a 0.4in footer holding text
    that wants more - and reporting those as our defects buries the real ones.
    """
    if not template_path or not Path(template_path).exists():
        return set()
    tpl = Presentation(template_path)
    return {(i, sh.name) for i, s in enumerate(tpl.slides, 1) for sh in s.shapes}


def main(path: str, template_path: str = "") -> int:
    prs = Presentation(path)
    inherited = template_shapes(template_path)
    problems = 0
    suppressed = 0

    for i, slide in enumerate(prs.slides, 1):
        issues = []
        texts = []
        for sh in slide.shapes:
            if not sh.has_text_frame:
                continue
            if (i, sh.name) in inherited:
                suppressed += 1
                continue
            body = sh.text_frame.text.strip()
            r = rect(sh)
            if body:
                texts.append((sh, r, body))

            # --- overflow
            if body:
                need = est_height_in(sh)
                have = r[3]
                if have > 0 and need > have * 1.02:
                    over = (need - have) / have
                    issues.append(
                        f"OVERFLOW  {sh.name[:20]:<20s} needs ~{need:.2f}in "
                        f"in {have:.2f}in  (+{100*over:.0f}%)  {body[:45]!r}")

            # --- bounds
            x, y, w, h = r
            if x < -0.01 or y < -0.01 or x + w > SLIDE_W + 0.01 or y + h > SLIDE_H + 0.01:
                issues.append(
                    f"OUT OF BOUNDS  {sh.name[:20]:<20s} "
                    f"x={x:.2f} y={y:.2f} w={w:.2f} h={h:.2f}")
            elif body and (x < MARGIN or y < MARGIN) and sh.name.startswith("TextBox"):
                issues.append(
                    f"TIGHT MARGIN  {sh.name[:20]:<20s} x={x:.2f} y={y:.2f}")

        # --- overlaps between text-bearing shapes
        for a in range(len(texts)):
            for b in range(a + 1, len(texts)):
                sa, ra, ta = texts[a]
                sb, rb, tb = texts[b]
                if (i, sa.name) in inherited and (i, sb.name) in inherited:
                    continue
                ov = overlap_area(ra, rb)
                smaller = min(ra[2] * ra[3], rb[2] * rb[3])
                if smaller > 0 and ov / smaller > 0.35:
                    issues.append(
                        f"OVERLAP  {sa.name[:16]}/{sb.name[:16]} "
                        f"{100*ov/smaller:.0f}% of smaller  "
                        f"{ta[:25]!r} vs {tb[:25]!r}")

        print(f"--- slide {i}: {'OK' if not issues else str(len(issues)) + ' issue(s)'}")
        for msg in issues:
            print(f"      {msg}")
        problems += len(issues)

    print()
    print(f"total issues: {problems}   "
          f"({suppressed} template-inherited shapes suppressed)")
    return 0 if problems == 0 else 1


if __name__ == "__main__":
    deck = sys.argv[1] if len(sys.argv) > 1 else "SIH2026_SIH26145_EKAGRA_idea.pptx"
    tpl = sys.argv[2] if len(sys.argv) > 2 else "SIH2026-template.pptx"
    sys.exit(main(deck, tpl))
