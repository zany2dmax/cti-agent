#!/usr/bin/env python3
"""Render CHEATSHEET.md to a printable PDF.

    python3 scripts/cheatsheet-pdf.py CHEATSHEET.md CHEATSHEET.pdf

Needs reportlab (pip3 install reportlab). Handles the markdown the cheat sheet
uses and nothing more: # and ## headings, paragraphs, "- " bullets, fenced code
blocks, pipe tables, and inline `code` and **bold**. Kept to one dependency
on purpose, so `task cheatsheet:pdf` works on a Mac without LaTeX or pandoc.
"""
import re
import sys
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (KeepTogether, ListFlowable, ListItem, Paragraph,
                                Preformatted, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

NAVY = colors.HexColor("#12203a")
GREY = colors.HexColor("#4a5568")
CODE_BG = colors.HexColor("#f4f5f7")
RULE = colors.HexColor("#d5dae1")

base = getSampleStyleSheet()
S = {
    "title": ParagraphStyle("title", parent=base["Title"], fontSize=18, leading=22,
                            textColor=NAVY, alignment=TA_LEFT, spaceAfter=6),
    "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=12.5, leading=15,
                         textColor=NAVY, spaceBefore=10, spaceAfter=4),
    "body": ParagraphStyle("body", parent=base["BodyText"], fontSize=9, leading=12,
                           spaceAfter=4),
    "cell": ParagraphStyle("cell", parent=base["BodyText"], fontSize=8, leading=10),
    "cellh": ParagraphStyle("cellh", parent=base["BodyText"], fontSize=8, leading=10,
                            textColor=colors.white, fontName="Helvetica-Bold"),
    "code": ParagraphStyle("code", parent=base["Code"], fontName="Courier",
                           fontSize=7.6, leading=9.6, textColor=colors.black,
                           backColor=CODE_BG, borderPadding=(4, 5, 4, 5),
                           leftIndent=5, rightIndent=5, spaceBefore=2, spaceAfter=7),
}


def inline(text):
    """Escape, then apply `code` and **bold**."""
    out, parts = [], re.split(r"(`[^`]+`)", text)
    for p in parts:
        if p.startswith("`") and p.endswith("`") and len(p) > 1:
            out.append('<font face="Courier" size="8">' + escape(p[1:-1]) + "</font>")
        else:
            e = escape(p)
            e = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", e)
            out.append(e)
    return "".join(out)


def table(rows):
    cells = [[c.strip() for c in r.strip().strip("|").split("|")] for r in rows]
    cells = [r for r in cells if not all(re.fullmatch(r":?-{3,}:?", c) for c in r)]
    head, body = cells[0], cells[1:]
    data = [[Paragraph(inline(c), S["cellh"]) for c in head]]
    data += [[Paragraph(inline(c), S["cell"]) for c in r] for r in body]
    n = len(head)
    width = 7.3 * inch
    first = 0.30 if n > 2 else 0.42
    widths = [width * first] + [width * (1 - first) / (n - 1)] * (n - 1)
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fb")]),
        ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def build(md):
    story, lines, i = [], md.splitlines(), 0
    para = []

    def flush():
        if para:
            story.append(Paragraph(inline(" ".join(para)), S["body"]))
            para.clear()

    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            flush()
            block = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                block.append(lines[i])
                i += 1
            story.append(Preformatted("\n".join(block), S["code"]))
        elif line.startswith("# "):
            flush()
            story.append(Paragraph(inline(line[2:]), S["title"]))
        elif line.startswith("## "):
            flush()
            # Keep a heading with what follows it.
            story.append(KeepTogether([Paragraph(inline(line[3:]), S["h2"])]))
        elif line.startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append(lines[i])
                i += 1
            story.append(table(rows))
            story.append(Spacer(1, 6))
            continue
        elif line.startswith("- "):
            flush()
            items = []
            while i < len(lines) and (lines[i].startswith("- ") or lines[i].startswith("  ")):
                if lines[i].startswith("- "):
                    items.append(lines[i][2:])
                else:
                    items[-1] += " " + lines[i].strip()
                i += 1
            story.append(ListFlowable(
                [ListItem(Paragraph(inline(t), S["body"]), leftIndent=10) for t in items],
                bulletType="bullet", start="•", leftIndent=12, bulletFontSize=7))
            continue
        elif not line.strip():
            flush()
        else:
            para.append(line.strip())
        i += 1
    flush()
    return story


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(GREY)
    canvas.drawString(0.6 * inch, 0.45 * inch, "CTI Agent Fleet - operator cheat sheet")
    canvas.drawRightString(7.9 * inch, 0.45 * inch, f"page {doc.page}")
    canvas.restoreState()


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: cheatsheet-pdf.py CHEATSHEET.md OUT.pdf")
    with open(sys.argv[1], encoding="utf-8") as fh:
        md = fh.read()
    doc = SimpleDocTemplate(sys.argv[2], pagesize=letter,
                            leftMargin=0.6 * inch, rightMargin=0.6 * inch,
                            topMargin=0.55 * inch, bottomMargin=0.7 * inch,
                            title="CTI Agent Fleet - operator cheat sheet")
    doc.build(build(md), onFirstPage=footer, onLaterPages=footer)
    print(f"wrote {sys.argv[2]}")


if __name__ == "__main__":
    main()
