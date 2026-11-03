package podlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/zany2dmax/cti-agent/internal/safelog"
)

// # AGGREGATES ONLY
//
// A Log API event is a whole mail record: sender, recipients, subject, message
// id, URLs. The fleet needs none of that to answer "does this domain send mail"
// and "who is spoofing us", so Aggregate keeps counts keyed by things that are
// not about a person: route names, result words, the DOMAIN part of a header
// From, DKIM signer/selector, and a sender IP. Nothing in it can be turned
// back into a recipient, a subject or an address, and the event itself is
// dropped as soon as it is counted.
//
// The keys in several maps come from mail anyone can send (a header From
// domain, a DKIM selector), so every key is capped in length, sanitised for
// logs, and the number of distinct keys per map is capped so a hostile stream
// cannot grow memory.

const (
	// MaxKeys is the most distinct keys any one map keeps; the rest are
	// counted under OverflowKey.
	MaxKeys     = 5000
	OverflowKey = "(other)"

	// OwnDomainRoute is the Proofpoint rule that matched one of the
	// organisation's own domains in the header From. On an inbound message it
	// is the "someone is using our name" signal; the guide does not name the
	// route, it is the tenant's rule name, seen in real events.
	OwnDomainRoute = "mydomains_from_hdr"

	// simulationPrefix marks the organisation's own phishing-awareness
	// simulations (KnowBe4 routes), which send as our domain on purpose and
	// must not be counted as spoofing.
	simulationPrefix = "knowbe4"
)

// event is the part of a message record this package reads. Every field is
// optional: the guide marks most of them so.
type event struct {
	TS         string `json:"ts"`
	Connection struct {
		IP string `json:"ip"`
	} `json:"connection"`
	Msg struct {
		Header struct {
			From strList `json:"from"`
		} `json:"header"`
		ParsedAddresses struct {
			From strList `json:"from"`
		} `json:"parsedAddresses"`
	} `json:"msg"`
	Filter *struct {
		QID            string   `json:"qid"`
		Routes         []string `json:"routes"`
		RouteDirection string   `json:"routeDirection"`
		Modules        struct {
			Dkimv []struct {
				Domain   string `json:"domain"`
				Selector string `json:"selector"`
				Result   string `json:"result"`
			} `json:"dkimv"`
			Spf struct {
				Result string `json:"result"`
			} `json:"spf"`
			Dmarc struct {
				FilterdResult string `json:"filterdResult"`
				AuthResults   []struct {
					Method string `json:"method"`
					Result string `json:"result"`
				} `json:"authResults"`
			} `json:"dmarc"`
		} `json:"modules"`
	} `json:"filter"`
}

// strList accepts a JSON string or an array of strings.
type strList []string

func (s *strList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var one string
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*s = strList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// SpoofStat is the inbound mail that carried one of our domains in its header
// From but was not one of our own simulations.
type SpoofStat struct {
	Total int            `json:"total"`
	DMARC map[string]int `json:"dmarc"`
}

// Aggregate is everything the fleet keeps from a read.
type Aggregate struct {
	Messages   int    `json:"messages"` // WebSocket messages
	Events     int    `json:"events"`   // JSON records (a message can hold several)
	Undecoded  int    `json:"undecoded"`
	NoFilter   int    `json:"noFilter"` // records without a filter object
	Bytes      int64  `json:"bytes"`
	MaxMessage int    `json:"maxMessageBytes"`
	FirstTS    string `json:"firstTs,omitempty"`
	LastTS     string `json:"lastTs,omitempty"`

	Direction map[string]int `json:"direction"`
	Routes    map[string]int `json:"routes"`
	DMARC     map[string]int `json:"dmarc"`
	SPF       map[string]int `json:"spf"`

	// Outbound: what our own mail looks like to the gateway.
	OutboundFrom   map[string]int `json:"outboundFromDomains"`
	OutboundIPs    map[string]int `json:"outboundSenderIPs"`
	OutboundDKIM   map[string]int `json:"outboundDkim"` // "signer/selector/result"
	OutboundEvents int            `json:"outboundEvents"`
	// OutboundUnattributed: outbound events with no usable header-From domain
	// (bounces, unparsable names). They are counted, never attributed.
	OutboundUnattributed int            `json:"outboundUnattributed"`
	OutboundWithDKIM     int            `json:"outboundWithDkim"`
	OutboundDKIMByFrom   map[string]int `json:"outboundDkimByFromDomain"`

	// Inbound mail using our name.
	Spoof          map[string]*SpoofStat `json:"spoof"`
	SpoofIPs       map[string]int        `json:"spoofSenderIPs"`
	SimulatedCount int                   `json:"ownSimulations"`

	first, last time.Time
}

// NewAggregate returns an empty Aggregate.
func NewAggregate() *Aggregate {
	return &Aggregate{
		Direction:          map[string]int{},
		Routes:             map[string]int{},
		DMARC:              map[string]int{},
		SPF:                map[string]int{},
		OutboundFrom:       map[string]int{},
		OutboundIPs:        map[string]int{},
		OutboundDKIM:       map[string]int{},
		OutboundDKIMByFrom: map[string]int{},
		Spoof:              map[string]*SpoofStat{},
		SpoofIPs:           map[string]int{},
	}
}

func key(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "(none)"
	}
	return safelog.LineMax(s, 120)
}

func bump(m map[string]int, k string) {
	if _, ok := m[k]; !ok && len(m) >= MaxKeys {
		k = OverflowKey
	}
	m[k]++
}

// AddMessage counts one WebSocket message. It never returns the event or any
// part of it, and a message that cannot be decoded is only counted.
func (a *Aggregate) AddMessage(msg []byte) {
	a.Messages++
	a.Bytes += int64(len(msg))
	if len(msg) > a.MaxMessage {
		a.MaxMessage = len(msg)
	}
	// The guide warns that archive data can carry control characters inside
	// the JSON (a raw newline in a subject, say), which JSON forbids in a
	// string. Turn every byte below 0x20 into a space before decoding;
	// whitespace between tokens is unaffected.
	if hasControl(msg) {
		msg = cleanControl(msg)
	}
	dec := json.NewDecoder(bytes.NewReader(msg))
	for {
		var ev event
		err := dec.Decode(&ev)
		if err == io.EOF {
			break
		}
		if err != nil {
			a.Undecoded++
			return
		}
		a.addEvent(&ev)
	}
}

func hasControl(b []byte) bool {
	for _, c := range b {
		if c < 0x20 {
			return true
		}
	}
	return false
}

func cleanControl(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c < 0x20 {
			c = ' '
		}
		out[i] = c
	}
	return out
}

func (a *Aggregate) addEvent(ev *event) {
	a.Events++
	a.noteTime(ev.TS)
	f := ev.Filter
	if f == nil {
		a.NoFilter++
		return
	}
	dir := key(f.RouteDirection)
	bump(a.Direction, dir)
	simulated, ownName := false, false
	for _, r := range f.Routes {
		rk := key(r)
		bump(a.Routes, rk)
		if strings.HasPrefix(rk, simulationPrefix) {
			simulated = true
		}
		if rk == OwnDomainRoute {
			ownName = true
		}
	}
	dmarc := key(f.Modules.Dmarc.FilterdResult)
	bump(a.DMARC, dmarc)
	spf := spfResult(ev)
	bump(a.SPF, spf)

	from := fromDomain(ev)
	switch dir {
	case "outbound":
		a.OutboundEvents++
		bump(a.OutboundFrom, key(from))
		if k := key(from); k == "(none)" || k == "(unparsed)" {
			a.OutboundUnattributed++
		}
		if ip := key(ev.Connection.IP); ip != "(none)" {
			bump(a.OutboundIPs, ip)
		}
		if len(f.Modules.Dkimv) > 0 {
			a.OutboundWithDKIM++
			bump(a.OutboundDKIMByFrom, key(from))
		}
		for _, d := range f.Modules.Dkimv {
			bump(a.OutboundDKIM, key(d.Domain)+"/"+key(d.Selector)+"/"+key(d.Result))
		}
	case "inbound":
		if !ownName {
			return
		}
		if simulated {
			a.SimulatedCount++
			return
		}
		st := a.Spoof[key(from)]
		if st == nil {
			if len(a.Spoof) >= MaxKeys {
				st = a.Spoof[OverflowKey]
				if st == nil {
					st = &SpoofStat{DMARC: map[string]int{}}
					a.Spoof[OverflowKey] = st
				}
			} else {
				st = &SpoofStat{DMARC: map[string]int{}}
				a.Spoof[key(from)] = st
			}
		}
		st.Total++
		bump(st.DMARC, dmarc)
		// Only the senders DMARC did not pass: a passing sender is one of our
		// own cloud services (it signs or aligns as us), and listing its
		// address beside the real offenders only buries them.
		if dmarc != "pass" {
			if ip := key(ev.Connection.IP); ip != "(none)" {
				bump(a.SpoofIPs, ip)
			}
		}
	}
}

func spfResult(ev *event) string {
	if r := ev.Filter.Modules.Spf.Result; r != "" {
		return key(r)
	}
	for _, ar := range ev.Filter.Modules.Dmarc.AuthResults {
		if strings.EqualFold(ar.Method, "spf") {
			return key(ar.Result)
		}
	}
	return "(none)"
}

func fromDomain(ev *event) string {
	list := ev.Msg.ParsedAddresses.From
	if len(list) == 0 {
		list = ev.Msg.Header.From
	}
	if len(list) == 0 {
		return ""
	}
	addr := strings.TrimSpace(list[0])
	if pa, err := mail.ParseAddress(addr); err == nil {
		addr = pa.Address
	}
	i := strings.LastIndex(addr, "@")
	if i < 0 {
		return ""
	}
	d := strings.ToLower(strings.TrimFunc(addr[i+1:], func(r rune) bool {
		return unicode.IsSpace(r) || r == '<' || r == '>' || r == '.' || r == '"'
	}))
	// Only a plausible host name becomes a report key: free text after an @
	// (a display name, a comment) must not.
	if !domainRE.MatchString(d) {
		return "(unparsed)"
	}
	return d
}

var domainRE = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)

// Span is the earliest and latest event time seen (zero when none parsed). A
// caller that needs to know the read covered its window compares these with it.
func (a *Aggregate) Span() (first, last time.Time) { return a.first, a.last }

func (a *Aggregate) noteTime(ts string) {
	if ts == "" {
		return
	}
	t, err := time.Parse("2006-01-02T15:04:05.999999999Z0700", ts)
	if err != nil {
		return
	}
	if a.first.IsZero() || t.Before(a.first) {
		a.first = t
		a.FirstTS = t.UTC().Format(time.RFC3339)
	}
	if t.After(a.last) {
		a.last = t
		a.LastTS = t.UTC().Format(time.RFC3339)
	}
}

type kv struct {
	K string
	V int
}

func top(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].V != out[j].V {
			return out[i].V > out[j].V
		}
		return out[i].K < out[j].K
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Report writes the aggregate as plain text. It prints counts and the keys
// above, nothing else.
func (a *Aggregate) Report(w io.Writer, n int) {
	p := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	section := func(title string, m map[string]int) {
		p("\n== %s ==\n", title)
		if len(m) == 0 {
			p("  (none)\n")
		}
		for _, e := range top(m, n) {
			p("  %7d  %s\n", e.V, e.K)
		}
	}
	p("Messages: %d (largest %d bytes, %d bytes total)\n", a.Messages, a.MaxMessage, a.Bytes)
	p("Events:   %d (no filter object: %d, undecodable messages: %d)\n", a.Events, a.NoFilter, a.Undecoded)
	if a.FirstTS != "" {
		p("Event times: %s to %s (UTC)\n", a.FirstTS, a.LastTS)
	}
	section("direction (routeDirection)", a.Direction)
	section("routes", a.Routes)
	section("DMARC rollup (filterdResult)", a.DMARC)
	section("SPF", a.SPF)

	p("\n== outbound: %d events, %d carry DKIM verification data ==\n", a.OutboundEvents, a.OutboundWithDKIM)
	section("outbound header-From domains", a.OutboundFrom)
	section("outbound sender IPs", a.OutboundIPs)
	section("outbound DKIM signer/selector/result", a.OutboundDKIM)

	p("\n== inbound mail using our domains in the header From ==\n")
	p("  own phishing simulations (excluded): %d\n", a.SimulatedCount)
	names := make([]string, 0, len(a.Spoof))
	for k := range a.Spoof {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		if a.Spoof[names[i]].Total != a.Spoof[names[j]].Total {
			return a.Spoof[names[i]].Total > a.Spoof[names[j]].Total
		}
		return names[i] < names[j]
	})
	if n > 0 && len(names) > n {
		names = names[:n]
	}
	if len(names) == 0 {
		p("  (none)\n")
	}
	for _, k := range names {
		st := a.Spoof[k]
		parts := make([]string, 0, len(st.DMARC))
		for _, e := range top(st.DMARC, 0) {
			parts = append(parts, fmt.Sprintf("%s=%d", e.K, e.V))
		}
		p("  %7d  %s  [dmarc: %s]\n", st.Total, k, strings.Join(parts, " "))
	}
	section("sender IPs of those messages that did not pass DMARC", a.SpoofIPs)
}
