package supplier

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/zany2dmax/cti-agent/internal/graph"
)

// Attachment is what the lane knows about a file before deciding to open it.
type Attachment struct {
	ID          string
	Name        string
	ContentType string
	Size        int64
	Inline      bool
	IsFile      bool
}

// Source is where attachments come from. It is an interface so the one rule
// that matters - the tax and bank files are never opened - is tested against a
// fake that records every download.
type Source interface {
	Attachments(ctx context.Context, messageID string) ([]Attachment, error)
	Content(ctx context.Context, messageID, attachmentID string, maxBytes int64) ([]byte, error)
}

// GraphSource reads a mailbox's attachments through Graph, read-only.
type GraphSource struct {
	Client  *graph.Client
	Mailbox string
}

func (g GraphSource) Attachments(ctx context.Context, messageID string) ([]Attachment, error) {
	infos, err := g.Client.Attachments(ctx, g.Mailbox, messageID)
	if err != nil {
		return nil, err
	}
	out := make([]Attachment, len(infos))
	for i, a := range infos {
		out[i] = Attachment{ID: a.ID, Name: a.Name, ContentType: a.ContentType, Size: a.Size, Inline: a.Inline, IsFile: a.IsFile}
	}
	return out, nil
}

func (g GraphSource) Content(ctx context.Context, messageID, attachmentID string, maxBytes int64) ([]byte, error) {
	return g.Client.AttachmentContent(ctx, g.Mailbox, messageID, attachmentID, maxBytes)
}

// Policy decides which attachments may be opened. The default reads .xlsx
// files only, so the scanned W-9 and bank PDFs (tax ids and account numbers)
// are never fetched at all, and a spreadsheet that is named like a tax or bank
// form is refused as well.
type Policy struct {
	// Exts are the file extensions that may be read, lowercase with the dot.
	// Empty means ".xlsx".
	Exts []string
	// MaxBytes is the largest file to download. Zero means 2 MiB; a real form
	// is about 50 KB.
	MaxBytes int64
}

func (p Policy) exts() []string {
	if len(p.Exts) == 0 {
		return []string{".xlsx"}
	}
	return p.Exts
}

func (p Policy) max() int64 {
	if p.MaxBytes <= 0 {
		return 2 << 20
	}
	return p.MaxBytes
}

// sensitiveWords are words that mark a file as a tax or bank document. They are
// matched as whole words of the file name, so "first" is not "irs".
var sensitiveWords = map[string]bool{
	"w9": true, "bank": true, "banking": true, "routing": true,
	"void": true, "voided": true, "tax": true, "irs": true, "ach": true,
}

// words splits a file name into lowercase words, with "w-9", "w 9" and "w_9"
// all becoming "w9".
func words(name string) []string {
	n := strings.ToLower(name)
	for _, sep := range []string{"w-9", "w 9", "w_9"} {
		n = strings.ReplaceAll(n, sep, "w9")
	}
	return strings.FieldsFunc(n, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
}

// Readable reports whether an attachment may be opened, and if not, why.
func (p Policy) Readable(a Attachment) (bool, string) {
	switch {
	case !a.IsFile:
		return false, "not a file attachment"
	case a.Inline:
		return false, "inline image"
	}
	ext := ""
	if i := strings.LastIndex(a.Name, "."); i >= 0 {
		ext = strings.ToLower(a.Name[i:])
	}
	ok := false
	for _, e := range p.exts() {
		if ext == e {
			ok = true
		}
	}
	if !ok {
		return false, "type not read"
	}
	for _, w := range words(a.Name) {
		if sensitiveWords[w] {
			return false, "named like a tax or bank form"
		}
	}
	if a.Size > p.max() {
		return false, "too large"
	}
	return true, ""
}

// Skipped is an attachment that was not opened, and why. Names are kept so the
// lane can say what it left alone.
type Skipped struct {
	Name   string
	Reason string
}

// FormRead is one readable attachment and what came of reading it as a form.
type FormRead struct {
	Name string
	Form Form
	// Err is set when the file was opened but is not a supplier form (or could
	// not be downloaded). The lane treats the request as having no readable form.
	Err error
}

// ReadForms lists a message's attachments, opens only those Policy allows, and
// reads each as a supplier form. Content is requested for no other attachment:
// this is the only path from a message to attachment bytes.
func ReadForms(ctx context.Context, src Source, p Policy, messageID string) ([]FormRead, []Skipped, error) {
	atts, err := src.Attachments(ctx, messageID)
	if err != nil {
		return nil, nil, fmt.Errorf("listing attachments: %w", err)
	}
	var reads []FormRead
	var skipped []Skipped
	for _, a := range atts {
		if ok, why := p.Readable(a); !ok {
			if why != "inline image" { // signature images are noise, not a decision
				skipped = append(skipped, Skipped{Name: a.Name, Reason: why})
			}
			continue
		}
		data, err := src.Content(ctx, messageID, a.ID, p.max())
		if err != nil {
			reads = append(reads, FormRead{Name: a.Name, Err: err})
			continue
		}
		f, err := Parse(data)
		reads = append(reads, FormRead{Name: a.Name, Form: f, Err: err})
	}
	return reads, skipped, nil
}
