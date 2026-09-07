"""Shared helpers for filling the official SIH 2026 idea template.

Extracted so both submissions (SIH26145 and SIH26153) use one implementation.
Two of these exist because of bugs that were invisible in a text dump:
`set_single_run` (setting every run to the full string duplicates the text) and
its `<a:br/>` cleanup (a leftover line break renders as a stray blank line).
"""

from __future__ import annotations

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

INK = RGBColor(0x14, 0x19, 0x18)
MUTED = RGBColor(0x55, 0x60, 0x5D)
GREY = RGBColor(0xB0, 0xBA, 0xB7)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
RUST = RGBColor(0xA3, 0x34, 0x1F)
PALE = RGBColor(0xF4, 0xF7, 0xF6)

BR_TAG = "{http://schemas.openxmlformats.org/drawingml/2006/main}br"
R_ID = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"


def delete_slide(prs: Presentation, index: int) -> None:
    """Remove a slide. python-pptx has no API for this."""
    sldIdLst = prs.slides._sldIdLst
    ids = list(sldIdLst)
    rId = ids[index].get(R_ID)
    sldIdLst.remove(ids[index])
    prs.part.drop_rel(rId)


def find(slide, predicate):
    for sh in slide.shapes:
        if predicate(sh):
            return sh
    return None


def by_name(slide, prefix):
    return find(slide, lambda s: s.name.startswith(prefix))


def set_single_run(shape, text, *, size=None):
    """Replace a shape's text, keeping the first run's formatting.

    Looping over `paragraph.runs` and assigning the full string to each one
    duplicates the text once per run - and it does not show up in a text dump,
    only in the render.
    """
    tf = shape.text_frame
    paras = list(tf.paragraphs)
    for extra in paras[1:]:
        extra._p.getparent().remove(extra._p)
    para = paras[0]
    runs = list(para.runs)
    if not runs:
        runs = [para.add_run()]
    runs[0].text = text
    if size is not None:
        runs[0].font.size = Pt(size)
    for extra in runs[1:]:
        extra._r.getparent().remove(extra._r)
    # <a:br/> elements are siblings of runs, so removing runs alone leaves a
    # trailing break that renders as a blank line.
    for br in para._p.findall(BR_TAG):
        para._p.remove(br)
    return runs[0]


def set_body(shape, blocks, *, accent, size=14, gap=6,
             left=None, top=None, width=None, height=None):
    """Fill a text box with styled blocks.

    Styles: 'h' section header, 'b' body, 'sub' muted sub-point,
    'k' key result, 'neg' a result that went against us.
    """
    if left is not None:
        shape.left = Emu(int(left * 914400))
    if top is not None:
        shape.top = Emu(int(top * 914400))
    if width is not None:
        shape.width = Emu(int(width * 914400))
    if height is not None:
        shape.height = Emu(int(height * 914400))

    tf = shape.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = MSO_ANCHOR.TOP

    for p in list(tf.paragraphs)[1:]:
        p._p.getparent().remove(p._p)
    first = tf.paragraphs[0]
    for r in list(first.runs):
        r._r.getparent().remove(r._r)

    for i, (text, style) in enumerate(blocks):
        para = first if i == 0 else tf.add_paragraph()
        para.alignment = PP_ALIGN.LEFT
        para.space_after = Pt(gap if style != "h" else gap + 2)
        para.space_before = Pt(8 if style == "h" and i else 0)
        para.level = 1 if style == "sub" else 0

        run = para.add_run()
        run.text = text
        f = run.font
        f.name = "Calibri"
        if style == "h":
            f.size, f.bold, f.color.rgb = Pt(size + 2), True, accent
        elif style == "k":
            f.size, f.bold, f.color.rgb = Pt(size), True, INK
        elif style == "neg":
            f.size, f.bold, f.color.rgb = Pt(size), True, RUST
        elif style == "sub":
            f.size, f.bold, f.color.rgb = Pt(size - 2), False, MUTED
        else:
            f.size, f.bold, f.color.rgb = Pt(size), False, INK


def add_box(slide, x, y, w, h, text, *, size=11, bold=False, color=INK,
            fill=None, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.MIDDLE,
            shape=MSO_SHAPE.ROUNDED_RECTANGLE):
    sh = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(w), Inches(h))
    if fill is None:
        sh.fill.background()
    else:
        sh.fill.solid()
        sh.fill.fore_color.rgb = fill
    sh.line.fill.background()
    sh.shadow.inherit = False
    tf = sh.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = Inches(0.06)
    tf.margin_top = tf.margin_bottom = Inches(0.03)
    p = tf.paragraphs[0]
    p.alignment = align
    r = p.add_run()
    r.text = text
    r.font.size = Pt(size)
    r.font.bold = bold
    r.font.name = "Calibri"
    r.font.color.rgb = color
    return sh


def add_label(slide, x, y, w, h, text, *, size=11, bold=False, color=INK,
              align=PP_ALIGN.LEFT):
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = 0
    tf.margin_top = tf.margin_bottom = 0
    p = tf.paragraphs[0]
    p.alignment = align
    r = p.add_run()
    r.text = text
    r.font.size = Pt(size)
    r.font.bold = bold
    r.font.name = "Calibri"
    r.font.color.rgb = color
    return tb


def prepare(template_path, team_name):
    """Open the template, drop the instruction slide, stamp team placeholders."""
    prs = Presentation(str(template_path))
    delete_slide(prs, 6)
    slides = list(prs.slides)
    for s in slides[1:]:
        oval = find(s, lambda sh: sh.has_text_frame
                    and "Your Team Name" in sh.text_frame.text)
        if oval is not None:
            set_single_run(oval, team_name, size=10)
    sub = find(slides[0], lambda sh: sh.has_text_frame
               and "TITLE PAGE" in sh.text_frame.text)
    if sub is not None:
        set_single_run(sub, "")
    return prs, slides


# --------------------------------------------------------------- infographics
# The template's own instruction slide says "avoid paragraphs and post your idea
# in points / diagrams / infographics / pictures". These are the primitives that
# make that possible without reaching for an image editor.

def add_stat(slide, x, y, w, h, value, label, *, accent, size=26,
             sub=None, fill=None):
    """A single large number with a caption under it.

    Numbers are this submission's differentiator, so they are given the visual
    weight normally spent on stock photography. The caption is what stops a bare
    figure being a boast - `0.981` means nothing, `0.981 F1 on a one-way tap`
    is a claim someone can check.
    """
    if fill is not None:
        bg = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x),
                                    Inches(y), Inches(w), Inches(h))
        bg.fill.solid()
        bg.fill.fore_color.rgb = fill
        bg.line.fill.background()
        bg.shadow.inherit = False

    tb = slide.shapes.add_textbox(Inches(x), Inches(y + 0.06), Inches(w), Inches(h))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.05)
    tf.margin_top = tf.margin_bottom = 0

    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = str(value)
    r.font.size, r.font.bold, r.font.name = Pt(size), True, "Calibri"
    r.font.color.rgb = accent

    p2 = tf.add_paragraph()
    p2.alignment = PP_ALIGN.CENTER
    p2.space_before = Pt(1)
    r2 = p2.add_run()
    r2.text = label
    r2.font.size, r2.font.name = Pt(9), "Calibri"
    r2.font.color.rgb = MUTED

    if sub:
        p3 = tf.add_paragraph()
        p3.alignment = PP_ALIGN.CENTER
        r3 = p3.add_run()
        r3.text = sub
        r3.font.size, r3.font.name, r3.font.italic = Pt(8), "Calibri", True
        r3.font.color.rgb = GREY
    return tb


def add_bar_chart(slide, x, y, w, h, categories, values, *, accent,
                  highlight=None, number_format="0.000", maximum=None):
    """A native PowerPoint bar chart.

    Native rather than a rendered image so it stays crisp at any zoom and can be
    restyled by whoever picks this deck up. `highlight` colours one bar
    differently - used to mark the control that narrowed our own claim, which is
    the bar we most want a judge to look at.
    """
    from pptx.chart.data import CategoryChartData
    from pptx.enum.chart import XL_CHART_TYPE, XL_LABEL_POSITION

    data = CategoryChartData()
    data.categories = categories
    data.add_series("", values)
    gf = slide.shapes.add_chart(XL_CHART_TYPE.BAR_CLUSTERED, Inches(x), Inches(y),
                                Inches(w), Inches(h), data)
    ch = gf.chart
    ch.has_title = False
    ch.has_legend = False

    plot = ch.plots[0]
    plot.gap_width = 60
    plot.has_data_labels = True
    dl = plot.data_labels
    dl.number_format = number_format
    dl.number_format_is_linked = False
    dl.position = XL_LABEL_POSITION.OUTSIDE_END
    dl.font.size = Pt(9)
    dl.font.bold = True
    dl.font.color.rgb = INK

    ser = plot.series[0]
    ser.format.fill.solid()
    ser.format.fill.fore_color.rgb = accent
    if highlight is not None:
        pt = ser.points[highlight]
        pt.format.fill.solid()
        pt.format.fill.fore_color.rgb = RUST

    cat = ch.category_axis
    cat.has_major_gridlines = False
    cat.format.line.fill.background()
    cat.tick_labels.font.size = Pt(9)
    cat.tick_labels.font.color.rgb = INK

    val = ch.value_axis
    val.has_major_gridlines = False
    val.visible = False
    if maximum is not None:
        val.maximum_scale = maximum
    return gf


def add_flow(slide, y, stages, *, accent, pale, ink, white, muted, grey,
             left=0.67, width=12.0, box_h=0.82, hot=()):
    """A left-to-right pipeline of labelled boxes with chevrons between them.

    `hot` indexes the stages to emphasise - the ones that carry the idea rather
    than the plumbing.
    """
    n = len(stages)
    gap = 0.26
    w = (width - gap * (n - 1)) / n
    for i, (name, sub) in enumerate(stages):
        cx = left + i * (w + gap)
        on = i in hot
        add_box(slide, cx, y, w, box_h, name, size=11, bold=True,
                color=white if on else ink,
                fill=accent if on else pale, align=PP_ALIGN.CENTER)
        if sub:
            add_label(slide, cx, y + box_h + 0.04, w, 0.5, sub, size=8,
                      color=muted, align=PP_ALIGN.CENTER)
        if i < n - 1:
            add_label(slide, cx + w + 0.02, y + box_h / 2 - 0.16, gap, 0.32,
                      "\u203a", size=15, bold=True, color=grey,
                      align=PP_ALIGN.CENTER)


def add_compare(slide, x, y, w, header, rows, *, accent, pale, ink, muted,
                white, col_w, row_h=0.44, size=9, head_h=0.34, ours_fill=None):
    """A comparison grid: existing approaches against ours.

    Added because 'innovation and uniqueness' is the single heaviest item in the
    SIH rubric (25%) and prose cannot carry it in the two to three minutes an
    evaluator spends on a deck. A grid can be read at a glance; a paragraph
    saying "unlike existing solutions..." cannot.

    The final row is ours and is filled, so the eye lands on the row that
    answers "what is new here" without needing a caption to say so.
    """
    xs, tot = [], sum(col_w)
    cx = x
    for cwi in col_w:
        xs.append(cx)
        cx += cwi / tot * w
    widths = [c / tot * w for c in col_w]

    for i, (cx0, cw, text) in enumerate(zip(xs, widths, header)):
        add_box(slide, cx0, y, cw - 0.04, head_h, text, size=size, bold=True,
                color=white, fill=accent,
                align=PP_ALIGN.LEFT if i == 0 else PP_ALIGN.LEFT)

    yy = y + head_h + 0.05
    for r, row in enumerate(rows):
        ours = (r == len(rows) - 1)
        fill = (ours_fill or pale) if ours else None
        for i, (cx0, cw, text) in enumerate(zip(xs, widths, row)):
            add_box(slide, cx0, yy, cw - 0.04, row_h, text,
                    size=size, bold=ours,
                    color=ink if ours else (ink if i == 0 else muted),
                    fill=fill, align=PP_ALIGN.LEFT)
        yy += row_h + 0.05
    return yy
