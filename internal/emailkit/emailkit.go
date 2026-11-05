// Package emailkit is the one place that says what a fleet email looks like.
//
// # WHY NOT A CSS FILE
//
// A shared stylesheet is the obvious way to keep every lane's email the same,
// and it cannot work: Outlook ignores linked stylesheets and strips or
// half-honours <style> blocks, which is why every fleet email is a table
// layout with inline styles. So the style is held here instead, as tokens
// (the palette, the font, the 640px card) and as the pieces every email is
// built from (header band, lead block, severity tiles, section headings,
// cards, footer with the FLEET_ATTRIBUTION credit). A lane calls the pieces;
// the inline CSS comes out of this package; changing a colour is a change in
// one file. emailkit_test.go fails the build when a lane that has moved over
// draws its own page shell again.
//
// Every string argument documented "plain" is escaped here; every one
// documented "HTML" is trusted markup the caller has already escaped.
package emailkit

import (
	"fmt"
	"html"
	"os"
	"strings"

	"github.com/zany2dmax/cti-agent/internal/attribution"
)

// The page, the header band and the text colours. Values come from
// tokens.json.
var (
	// Font is the fleet emails' font stack; Mono is for paths and file names.
	Font = tok.Font
	Mono = tok.Mono

	PageBG   = tok.PageBG
	Navy     = tok.Navy
	BandText = tok.BandText
	Ink      = tok.Ink
	Soft     = tok.Soft
	Muted    = tok.Muted
	Rule     = tok.Rule
)

// Tone is one colour pair: the strong colour (text, borders, the tile's top
// edge) and its pale tint (the background).
type Tone struct{ Fg, Bg string }

// The palette. Red is for what needs action, Amber for what needs review,
// Yellow for caution between them, Blue for information and change, Green for
// all clear, Grey for neutral counts, Violet for the gateway section.
var (
	Red    = tone("red")
	Amber  = tone("amber")
	Yellow = tone("yellow")
	Blue   = tone("blue")
	Green  = tone("green")
	Grey   = tone("grey")
	Violet = tone("violet")
)

func esc(s string) string { return html.EscapeString(s) }

// Open writes the page: the document head, the grey page, the 640px card and
// the navy header band. org, heading and subtitle are plain; subtitle may be
// empty.
func Open(b *strings.Builder, title, org, heading, subtitle string) {
	OpenBand(b, title, Navy, org, heading, subtitle)
}

// OpenBand is Open with the header band in another colour. An alert uses it so
// that the band says failure, hold or test before a word is read; every other
// email keeps the navy band.
func OpenBand(b *strings.Builder, title, band, org, heading, subtitle string) {
	fmt.Fprintf(b, `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title></head>
<body style="margin:0;padding:0;background:%s">
<table width="100%%" cellpadding="0" cellspacing="0" role="presentation"
       style="background:%s"><tr><td align="center" style="padding:16px 8px">
<table width="640" cellpadding="0" cellspacing="0" role="presentation"
       style="max-width:640px;background:#fff;border-radius:6px;overflow:hidden">

  <tr><td style="background:%s;padding:16px 20px">
    <div style="font:700 12px %s;color:%s;letter-spacing:1.2px;text-transform:uppercase">%s</div>
    <div style="font:700 17px %s;color:#fff">%s</div>`,
		esc(title), PageBG, PageBG, band, Font, BandText, esc(org), Font, esc(heading))
	if subtitle != "" {
		fmt.Fprintf(b, `
    <div style="font:400 12px %s;color:%s;margin-top:3px">%s</div>`, Font, BandText, esc(subtitle))
	}
	b.WriteString("</td></tr>\n")
}

// Lead writes the coloured block under the header: the one thing to read.
// inner is HTML.
func Lead(b *strings.Builder, t Tone, inner string) {
	fmt.Fprintf(b, `
  <tr><td style="padding:16px 20px 0 20px">
    <table width="100%%" cellpadding="0" cellspacing="0" role="presentation">
      <tr><td style="background:%s;border-left:4px solid %s;padding:12px 14px;
                     font:400 14px/1.55 %s;color:%s">%s</td></tr>
    </table></td></tr>
`, t.Bg, t.Fg, Font, Ink, inner)
}

// Tile is one count in the row of tiles.
type Tile struct {
	Label string // plain; shown in capitals
	N     int
	Tone  Tone
}

// Tiles writes a row of equal-width counts. caption is HTML shown under them,
// or "".
func Tiles(b *strings.Builder, tiles []Tile, caption string) {
	b.WriteString(`
  <tr><td style="padding:14px 20px 0 20px">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation"><tr>`)
	w := 100
	if len(tiles) > 0 {
		w = 100 / len(tiles)
	}
	for _, t := range tiles {
		fmt.Fprintf(b, `
      <td width="%d%%" align="center" style="background:%s;border-top:3px solid %s;padding:10px 4px">
        <div style="font:700 24px %s;color:%s">%d</div>
        <div style="font:700 10px %s;color:%s;letter-spacing:.5px">%s</div></td>`,
			w, t.Tone.Bg, t.Tone.Fg, Font, t.Tone.Fg, t.N, Font, t.Tone.Fg, esc(strings.ToUpper(t.Label)))
	}
	b.WriteString(`
    </tr></table>`)
	if caption != "" {
		fmt.Fprintf(b, `
    <div style="font:400 11px/1.5 %s;color:%s;margin-top:5px">%s</div>`, Font, Muted, caption)
	}
	b.WriteString("</td></tr>\n")
}

// BodyOpen and BodyClose wrap the rows between the tiles and the footer:
// sections, cards and notes are rows of this table.
func BodyOpen(b *strings.Builder) {
	b.WriteString(`
  <tr><td style="padding:16px 20px 4px 20px">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation">`)
}

// BodyClose ends what BodyOpen began.
func BodyClose(b *strings.Builder) {
	b.WriteString(`
    </table></td></tr>`)
}

// Section is the underlined capitals heading. title is plain; colour is the
// tone's Fg (or Navy for the main sections).
func Section(b *strings.Builder, title, colour string) {
	fmt.Fprintf(b, `
      <tr><td style="padding:6px 0 8px 0">
        <div style="font:700 13px %s;color:%s;letter-spacing:.6px;text-transform:uppercase;
                    border-bottom:2px solid %s;padding-bottom:5px">%s</div></td></tr>`,
		Font, colour, colour, esc(title))
}

// Item is a plain paragraph row in a body table. text is plain.
func Item(b *strings.Builder, text string) {
	fmt.Fprintf(b, `
      <tr><td style="padding:0 0 8px 0">
        <div style="font:400 13px/1.55 %s;color:%s">%s</div></td></tr>`, Font, Soft, esc(text))
}

// Card is a row with a coloured left edge: a bold title and lines under it.
// title is plain; lines is HTML.
func Card(b *strings.Builder, t Tone, title, lines string) {
	fmt.Fprintf(b, `
      <tr><td style="padding:0 0 10px 0">
        <table width="100%%" cellpadding="0" cellspacing="0" role="presentation"
               style="border-left:4px solid %s;background:%s;border-radius:0 4px 4px 0">
          <tr><td style="padding:10px 13px">
            <div style="font:700 14px %s;color:%s">%s</div>
            <div style="font:400 13px/1.5 %s;color:%s">%s</div>
          </td></tr></table></td></tr>`, t.Fg, t.Bg, Font, Ink, esc(title), Font, Ink, lines)
}

// Callout is a full-width box with a coloured left edge, between the lead and
// the body: "the scan did not log in", "the report is attached". inner is HTML.
func Callout(b *strings.Builder, t Tone, inner string) {
	fmt.Fprintf(b, `
  <tr><td style="padding:14px 20px 0 20px">
    <div style="font:400 13px/1.55 %s;color:%s;background:%s;padding:10px 12px;
                border-left:4px solid %s">%s</div></td></tr>
`, Font, Ink, t.Bg, t.Fg, inner)
}

// Note is small grey text under the body, for notices that are not findings.
// inner is HTML.
func Note(b *strings.Builder, inner string) {
	fmt.Fprintf(b, `
  <tr><td style="padding:14px 20px 16px 20px">
    <div style="font:400 12px/1.6 %s;color:%s">%s</div></td></tr>
`, Font, Soft, inner)
}

// Foot writes the footer and closes the page. lines are HTML, shown one under
// another in small grey type; the last is usually Credit.
func Foot(b *strings.Builder, lines ...string) {
	fmt.Fprintf(b, `
  <tr><td style="padding:8px 20px 18px 20px;border-top:1px solid %s">
    <div style="font:400 11px/1.6 %s;color:%s">
      %s
    </div></td></tr>
`, Rule, Font, Muted, strings.Join(lines, "<br>\n      "))
	Close(b)
}

// Close ends the page. Foot calls it; a lane with a footer of its own (Patch
// Tuesday's sources list) writes that and calls Close.
func Close(b *strings.Builder) {
	b.WriteString("\n</table></td></tr></table></body></html>")
}

// Org is the organisation name for the header band: FLEET_ORG, else "Security".
func Org() string {
	if s := strings.TrimSpace(os.Getenv("FLEET_ORG")); s != "" {
		return s
	}
	return "Security"
}

// Credit is the footer's credit line, HTML: the configured attribution
// (FLEET_ATTRIBUTION, FLEET_REPO_URL) when there is one, otherwise the plain
// fallback the lane has always carried. who names the lane in the warning
// about a refused URL; fallback is plain.
func Credit(org, who, fallback string) string {
	if a := attribution.Load(org, who); !a.Empty() {
		return a.HTML(Blue.Fg)
	}
	return esc(fallback)
}

// CreditText is Credit for the plain-text part.
func CreditText(org, who, fallback string) string {
	if a := attribution.Load(org, who); !a.Empty() {
		return a.Text()
	}
	return fallback
}
