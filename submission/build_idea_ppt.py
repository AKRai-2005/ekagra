"""Build the SIH 2026 idea-submission PPT for SIH26145 from the official template.

Constraints taken from the official template's own instruction slide:
  - maximum six slides INCLUDING the title slide
  - use the provided template, keeping its prescribed section headings
  - points / diagrams / infographics, not paragraphs
  - export to PDF; the portal accepts nothing else

Every number in this deck is reproducible from the repository in this folder.
Nothing is claimed here that the experiments did not survive.
"""

from __future__ import annotations

import copy
from pathlib import Path

from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Inches, Pt

from deckkit import (
    GREY, INK, MUTED, PALE, WHITE,
    add_bar_chart, add_box, add_compare, add_flow, add_label, add_stat,
    by_name, find, prepare, set_body, set_single_run,
)

TEAL = RGBColor(0x0B, 0x6B, 0x63)
RUST = RGBColor(0xA3, 0x34, 0x1F)

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE / "SIH2026-template.pptx"
OUT = HERE / "SIH2026_SIH26145_EKAGRA_idea.pptx"

TEAM_NAME = "AlgoRhythms"
TEAM_ID = "[TEAM ID]"


# ------------------------------------------------------------------- content

def build() -> None:
    prs, (s1, s2, s3, s4, s5, s6) = prepare(TEMPLATE, TEAM_NAME)

    # ---------------------------------------------------------------- slide 1
    tb = by_name(s1, "TextBox")
    set_body(tb, [
        ("Problem Statement ID  -  SIH26145", "k"),
        ("AI-Based Detection of Cyber Threats in Unidirectional IP Traffic", "b"),
        ("Organisation  -  National Technical Research Organisation (NTRO)", "sub"),
        ("Theme  -  Blockchain & Cybersecurity", "sub"),
        ("PS Category  -  Software", "sub"),
        (f"Team ID  -  {TEAM_ID}", "sub"),
        (f"Team Name  -  {TEAM_NAME}", "sub"),
    ], accent=TEAL, size=14, gap=5, left=0.36, top=2.35, width=6.0, height=4.6)

    # ---------------------------------------------------------------- slide 2
    # Slide 2 carries the whole argument, so it is built as an infographic: the
    # ablation is a chart rather than a sentence, and the control that narrowed
    # our own claim is the highlighted bar. A judge who reads only this slide
    # should still leave knowing what we measured and what it cost us.
    set_single_run(by_name(s2, "Title"),
                   "EKAGRA  -  detection that survives a one-way tap", size=30)

    set_body(by_name(s2, "TextBox"), [
        ("A read-only sensor for a data diode. It keeps 60-second per-host state, so it "
         "detects threats from ONE direction of traffic - with no return path, no "
         "threat-intel lookup, and no payload decryption.", "b"),
    ], accent=TEAL, size=13, gap=4, left=0.67, top=1.28, width=12.0, height=0.62)

    # Innovation and uniqueness is the heaviest item in the SIH rubric (25%) and
    # cannot be carried by prose in a 2-minute read. A grid can be scanned.
    add_label(s2, 0.67, 1.98, 7.5, 0.28,
              "WHY EXISTING SOLUTIONS CANNOT BE DEPLOYED HERE",
              size=10, bold=True, color=TEAL)
    add_compare(
        s2, 0.67, 2.30, 7.5,
        ("Approach", "What it requires", "Why it fails behind a diode"),
        [("Suricata / Zeek", "signature feeds, both\ndirections of a flow",
          "the rule-update path IS an\negress path the diode forbids"),
         ("Darktrace / Vectra\n(commercial NDR)", "cloud analytics,\n$8-22 per IP per year",
          "foreign SaaS callback, recurring\nlicence, telemetry leaves India"),
         ("Owl / Waterfall\n(diode vendors)", "hardware one-way link",
          "they move data one way -\nthey do not detect threats in it"),
         ("EKAGRA", "a one-way tap.\nNothing else.",
          "purpose-built for the constraint:\n0.981 F1, zero licence, air-gapped")],
        accent=TEAL, pale=RGBColor(0xE2, 0xEF, 0xED), ink=INK, muted=MUTED,
        white=WHITE, col_w=(2.15, 2.35, 3.5), row_h=0.50, size=8.5)

    add_label(s2, 8.45, 1.98, 4.3, 0.28,
              "MEASURED  ·  CIC-IDS2017  ·  877,801 REAL FLOWS",
              size=10, bold=True, color=TEAL)
    add_bar_chart(s2, 8.15, 2.28, 4.75, 1.95,
                  ["Conventional IDS,\nput behind the tap", "EKAGRA,\nbuilt for the tap"],
                  [0.6903, 0.9810],
                  accent=TEAL, highlight=0, maximum=1.0)
    add_label(s2, 8.45, 4.28, 4.3, 0.55,
              "Same traffic, same temporal split. The gap is not lost direction - "
              "it is lost per-host state, and that is recoverable.",
              size=9.5, color=MUTED)

    stats = [
        ("0.9810", "binary-F1 on a one-way tap", "877,801 real flows"),
        ("Rs 0 / year", "licence cost", "vs Rs 13-37 lakh for NDR at 2,000 IPs"),
        ("672 Mbps", "measured throughput", "not the 1 Gbps we first claimed"),
        ("17 / 42", "own predictions refuted", "verdicts printed by the run"),
    ]
    for i, (v, lab, sub) in enumerate(stats):
        add_stat(s2, 0.67 + i * 3.06, 4.98, 2.90, 1.12, v, lab,
                 accent=TEAL, size=20, sub=sub, fill=PALE)

    add_label(s2, 0.67, 6.22, 12.0, 0.6,
              "Uniqueness: not another classifier. We measured what a one-way tap can "
              "actually observe, built a sensor to that profile, and ship every claim with "
              "the control that narrows it - including the ones that cost us.",
              size=10, color=MUTED)

    # ---------------------------------------------------------------- slide 3
    body = by_name(s3, "TextBox")
    set_body(body, [
        ("Stack  -  Python 3.12, XGBoost, NumPy/Pandas, PyTorch, pytest. "
         "No external service in the detection path, by design.", "b"),
    ], accent=TEAL, size=12, gap=4, left=0.67, top=1.30, width=12.0, height=0.55)

    stages = [
        ("Packets", "one-way tap"),
        ("Flow\nassembler", "idle 15s / active 120s"),
        ("Streaming\nhost-window", "HLL, Count-Min,\nMisra-Gries"),
        ("Detector\nheads", "6 threat classes"),
        ("Calibration\n+ evidence", "abstain, hash-chained"),
    ]
    x, w, gap_x = 0.67, 2.22, 0.28
    for i, (name, sub) in enumerate(stages):
        cx = x + i * (w + gap_x)
        fill = TEAL if i in (1, 2) else RGBColor(0xEE, 0xF1, 0xF0)
        col = WHITE if i in (1, 2) else INK
        add_box(s3, cx, 2.00, w, 0.95, name, size=12, bold=True, color=col,
                fill=fill, align=PP_ALIGN.CENTER)
        add_label(s3, cx, 3.02, w, 0.55, sub, size=9, color=MUTED,
                  align=PP_ALIGN.CENTER)
        if i < len(stages) - 1:
            add_label(s3, cx + w + 0.02, 2.28, gap_x, 0.4, ">", size=16,
                      bold=True, color=GREY, align=PP_ALIGN.CENTER)

    add_label(s3, 0.67, 3.60,
              12.0, 0.3,
              "One-way data flow. No component downstream of ingest can call anything upstream.",
              size=10, color=MUTED)

    body2 = s3.shapes.add_textbox(Inches(0.67), Inches(4.00), Inches(12.0), Inches(2.7))
    set_body(body2, [
        ("Streaming, not batch  -  as the problem statement requires", "h"),
        ("Single pass, bounded memory: 225,907 flows/s, 2.58 MB of state for 14,817 hosts, "
         "75 s end-to-end latency (60 s window + 15 s lateness budget).", "b"),
        ("Estimators start exact and promote to sketches only above 256 distinct values, "
         "so 14 of 16 features are bitwise identical to an exact batch computation.", "b"),
        ("Read-only enforced, not asserted", "h"),
        ("A CI test fails the build if anything in the detection path opens a socket. "
         "Sharded across processes by host: 2.70x to 119,918 packets/s (672 Mbps).", "b"),
    ], accent=TEAL, size=12, gap=5)

    # ---------------------------------------------------------------- slide 4
    # The official template asks this section for "potential challenges and
    # risks". Our own refuting control belongs here, not on slide 2: it is a
    # finding about the limits of the idea, which is exactly what this section
    # is for.
    body = by_name(s4, "TextBox")
    set_body(body, [
        ("Built and measured, not proposed  -  288 tests, one-command reproduction, on "
         "generated traffic, the corrected CIC-IDS2017 re-extraction (Zenodo 22016274), "
         "and a live capture from an ordinary laptop.", "b"),
    ], accent=TEAL, size=12, gap=4, left=0.67, top=1.28, width=12.0, height=0.60)

    add_label(s4, 0.67, 1.94, 6.6, 0.28,
              "THE CONTROL THAT NARROWED OUR OWN HEADLINE",
              size=10, bold=True, color=RUST)
    add_bar_chart(s4, 0.45, 2.22, 6.9, 2.35,
                  ["D  host-window ONLY (control)", "C  purpose-built sensor",
                   "B  deployed on one-way tap", "A  full visibility"],
                  [0.9812, 0.9810, 0.6903, 0.9793],
                  accent=TEAL, highlight=0, maximum=1.0)
    add_label(s4, 0.67, 4.66, 6.6, 0.95,
              "Those 16 host-window features alone score 0.9812 - level with full "
              "visibility. On this corpus the visibility question largely dissolves, so we "
              "narrowed the claim instead of defending it. A stress test then showed the "
              "reverse at low attack density: keep host state, never run on it alone.",
              size=9.5, color=INK)
    add_label(s4, 0.67, 5.72, 6.6, 0.9,
              "Method: predictions are written into each experiment before it runs and the "
              "run prints the verdict. 17 of 42 were refuted - our headline among them.",
              size=9.5, color=MUTED)

    add_label(s4, 7.55, 1.94, 5.2, 0.28, "RISKS WE CAN NAME, WITH MITIGATIONS",
              size=10, bold=True, color=TEAL)
    risks = [
        ("Throughput", "672 Mbps measured, not 1 Gbps",
         "Per-shard ceiling is ~880k pkt/s; the gap is coordination. Kernel RSS / "
         "AF_PACKET fanout removes it."),
        ("Corpus", "CIC-IDS2017 attacks are bursty",
         "Re-timed so attacks share cells with benign traffic: the one-way tap result "
         "holds, host-window-alone does not."),
        ("Encrypted web", "we called QUIC a hard ceiling - we were wrong",
         "UDP/443 beat TCP/443 80,291 to 32,069 in our own capture. QUIC Initial keys "
         "derive from the connection ID in the clear (RFC 9001), so we read those "
         "handshakes. 1-RTT payload stays out of reach."),
    ]
    for i, (k, risk, mit) in enumerate(risks):
        y = 2.24 + i * 1.52
        add_box(s4, 7.55, y, 5.2, 1.42, "", fill=RGBColor(0xF4, 0xF7, 0xF6))
        add_label(s4, 7.75, y + 0.10, 4.8, 0.26, k, size=11, bold=True, color=TEAL)
        add_label(s4, 7.75, y + 0.38, 4.8, 0.28, risk, size=10, bold=True, color=INK)
        add_label(s4, 7.75, y + 0.66, 4.8, 0.68, mit, size=9, color=MUTED)

    # ---------------------------------------------------------------- slide 5
    body = by_name(s5, "TextBox")
    set_body(body, [
        ("Beneficiaries  -  NTRO and NCIIPC-designated Critical Information "
         "Infrastructure: defence, power grid, banking, telecom and any enclave already "
         "behind a data diode.", "b"),
    ], accent=TEAL, size=12, gap=4, left=0.67, top=1.28, width=12.0, height=0.60)

    impact = [
        ("Rs 13-37 lakh", "recurring licence avoided, per enclave, per year",
         "NDR at $8-22 per protected IP (Vectra published metric), 2,000 IPs"),
        ("29.44 lakh", "cyber incidents CERT-In handled in 2025",
         "up 85% since 2023 - the volume this must scale into"),
        ("0", "outbound connections in the detection path",
         "CI-enforced: the build fails if anything opens a socket"),
    ]
    for i, (v, lab, sub) in enumerate(impact):
        add_stat(s5, 0.67 + i * 4.10, 1.96, 3.90, 1.16, v, lab,
                 accent=TEAL, size=21, sub=sub, fill=PALE)

    cards = [
        ("Economic  -  removes a licence AND an egress path",
         "A threat-intel callback is itself a hole in the diode. We measured a 55%-recall "
         "IP-reputation feed as net negative (0.926 to 0.971 without it): removing it "
         "improved detection and closed the path."),
        ("Sovereign by construction",
         "No foreign SaaS anywhere in the detection path and no telemetry leaving India - "
         "a Critical Information Infrastructure requirement, not a preference. "
         "Atmanirbhar Bharat, Digital India."),
        ("Operationally honest",
         "Conformal abstention: the sensor says 'I do not know' at a calibrated rate "
         "instead of guessing. Every alert carries hash-chained, tamper-evident evidence "
         "an auditor can verify offline."),
        ("Transferable  -  one core, two problem statements",
         "The same engineering core serves SIH26153. The visibility-profile procedure "
         "generalises to any sensor placement: characterise what the tap can observe, "
         "then train under that. SDG 9 and SDG 16."),
    ]
    for i, (h, t) in enumerate(cards):
        cx = 0.67 + (i % 2) * 6.15
        cy = 3.36 + (i // 2) * 1.72
        add_box(s5, cx, cy, 5.85, 1.58, "", fill=RGBColor(0xF4, 0xF7, 0xF6))
        add_label(s5, cx + 0.22, cy + 0.14, 5.4, 0.30, h, size=11.5, bold=True, color=TEAL)
        add_label(s5, cx + 0.22, cy + 0.50, 5.4, 0.98, t, size=10, color=INK)

    # ---------------------------------------------------------------- slide 6
    body = by_name(s6, "TextBox")
    set_body(body, [
        ("Datasets", "h"),
        ("Huang, Bois & Marchioro - Corrected CICFlowMeter Datasets: CIC-IDS 2017. "
         "Zenodo 22016274 (CC-BY-4.0). Chosen over the original CSVs, which have "
         "documented label and feature-extractor defects.", "b"),
        ("Engelen, Rimmer & Joosen - Troubleshooting an Intrusion Detection Dataset: "
         "the CICIDS2017 case study. IEEE S&P Workshops, 2021.", "b"),
        ("Method and prior art", "h"),
        ("Network Intrusion Datasets: A Survey, Limitations and Recommendations - "
         "arXiv:2502.06688.", "b"),
        ("Using JA4+ Fingerprints for Malware Detection in Encrypted Traffic - CNSM 2024. "
         "Basis for detecting malware in TLS from metadata alone, with no decryption.", "b"),
        ("MITRE ATT&CK for threat-stage mapping; NIST SP 800-53 and CIS Benchmarks for "
         "control alignment. RFC 9001 (QUIC-TLS) and RFC 8701 (GREASE) for the "
         "encrypted-traffic path.", "b"),
        ("Scale and market", "h"),
        ("CERT-In / PIB: 29.44 lakh incidents handled in 2025, up 85% on 2023; 9,700+ "
         "audits in 2024-25. MarketsandMarkets: NDR $3.68B (2025) to $5.82B (2030); "
         "data-diode and unidirectional-gateway market $0.56B (2026) to $0.77B (2031).", "b"),
        ("Our work", "h"),
        ("Repository with all experiments, pre-registered predictions and verdicts, and "
         "one-command reproduction: [REPO URL]", "b"),
    ], accent=TEAL, size=11.5, gap=4, left=0.67, top=1.30, width=12.0, height=5.4)

    prs.save(str(OUT))
    print(f"wrote {OUT}")
    print(f"slides: {len(prs.slides.__iter__.__self__._sldIdLst)}")


if __name__ == "__main__":
    build()
