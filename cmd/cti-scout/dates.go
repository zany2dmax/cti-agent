package main

// A feed entry's date, read as the Python lane read it: RFC 822 first
// (email.utils.parsedate_to_datetime, what RSS uses), then ISO 8601
// (datetime.fromisoformat, what Atom uses). Both are ported rule for rule,
// odd corners included, because the date decides whether an entry is inside
// the window, and the stored "published" text is its isoformat().

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

// pdt is a Python datetime: naive when hasTZ is false (local time, as
// astimezone() reads it), otherwise at a fixed offset in microseconds.
type pdt struct {
	y, mo, d, h, mi, s, us int
	hasTZ                  bool
	off                    int64
}

func (t pdt) isoformat() string {
	out := fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d", t.y, t.mo, t.d, t.h, t.mi, t.s)
	if t.us != 0 {
		out += fmt.Sprintf(".%06d", t.us)
	}
	if t.hasTZ {
		off, sign := t.off, "+"
		if off < 0 {
			off, sign = -off, "-"
		}
		us := off % 1e6
		secs := off / 1e6
		out += fmt.Sprintf("%s%02d:%02d", sign, secs/3600, secs/60%60)
		if secs%60 != 0 || us != 0 {
			out += fmt.Sprintf(":%02d", secs%60)
		}
		if us != 0 {
			out += fmt.Sprintf(".%06d", us)
		}
	}
	return out
}

// utc is pdt.astimezone(timezone.utc): a naive time is local time.
func (t pdt) utc() time.Time {
	if !t.hasTZ {
		return time.Date(t.y, time.Month(t.mo), t.d, t.h, t.mi, t.s, t.us*1000, time.Local).UTC()
	}
	return time.Date(t.y, time.Month(t.mo), t.d, t.h, t.mi, t.s, t.us*1000, time.UTC).
		Add(-time.Duration(t.off) * time.Microsecond)
}

func daysIn(y, m int) int {
	return time.Date(y, time.Month(m)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// valid is the datetime constructor's check.
func (t pdt) valid() bool {
	return t.y >= 1 && t.y <= 9999 && t.mo >= 1 && t.mo <= 12 && t.d >= 1 && t.d <= daysIn(t.y, t.mo) &&
		t.h >= 0 && t.h <= 23 && t.mi >= 0 && t.mi <= 59 && t.s >= 0 && t.s <= 59 && t.us >= 0 && t.us <= 999999
}

// parseDate is the lane's parse_date: nil when neither form reads it.
func parseDate(raw string) *pdt {
	if raw == "" {
		return nil
	}
	raw = pyStrip(raw)
	if t := parsedateToDatetime(raw); t != nil {
		return t
	}
	return fromisoformat(strings.ReplaceAll(raw, "Z", "+00:00"))
}

var (
	monthNames = []string{"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
		"january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"}
	dayNames  = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
	timezones = map[string]int{"UT": 0, "UTC": 0, "GMT": 0, "Z": 0, "AST": -400, "ADT": -300, "EST": -500, "EDT": -400,
		"CST": -600, "CDT": -500, "MST": -700, "MDT": -600, "PST": -800, "PDT": -700}
)

func index(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}

// pyInt is int(s) for a str: surrounding whitespace, a sign, Unicode decimal
// digits, single underscores between digits. A value past any date's range
// is clamped (it fails the range check either way).
func pyInt(s string) (int, bool) {
	r := []rune(pyStrip(s))
	neg := false
	if len(r) > 0 && (r[0] == '+' || r[0] == '-') {
		neg = r[0] == '-'
		r = r[1:]
	}
	if len(r) == 0 {
		return 0, false
	}
	n, digits := 0, 0
	for i, c := range r {
		if c == '_' {
			if i == 0 || i == len(r)-1 || r[i-1] == '_' {
				return 0, false
			}
			continue
		}
		if !unicode.IsDigit(c) {
			return 0, false
		}
		v := digitValue(c)
		if v < 0 {
			return 0, false
		}
		digits++
		if n < 1e15 {
			n = n*10 + v
		}
	}
	if digits == 0 {
		return 0, false
	}
	if neg {
		n = -n
	}
	return n, true
}

// digitValue is a decimal digit's value: ASCII, or another script's, whose
// ten digits run from a zero. A digit whose run cannot be told apart from
// the next is refused.
func digitValue(c rune) int {
	if c >= '0' && c <= '9' {
		return int(c - '0')
	}
	for z := c - 1; z >= c-10 && z >= 0; z-- {
		if !unicode.IsDigit(z) {
			return int(c - z - 1)
		}
	}
	return -1
}

func lastIs(s string, b byte) bool { return len(s) > 0 && s[len(s)-1] == b }

// parsedateTZ is email._parseaddr._parsedate_tz. ok is false where it
// returned None or raised. tz is nil for no zone or "-0000".
func parsedateTZ(data string) (f [6]int, tz *int, ok bool) {
	toks := strings.FieldsFunc(data, pySpace)
	if len(toks) == 0 {
		return f, nil, false
	}
	if strings.HasSuffix(toks[0], ",") || index(dayNames, strings.ToLower(toks[0])) >= 0 {
		toks = toks[1:]
	} else if i := strings.LastIndex(toks[0], ","); i >= 0 {
		toks[0] = toks[0][i+1:]
	}
	if len(toks) == 3 {
		if stuff := strings.Split(toks[0], "-"); len(stuff) == 3 {
			toks = append(stuff, toks[1:]...)
		}
	}
	if len(toks) == 4 {
		s := toks[3]
		i := strings.Index(s, "+")
		if i == -1 {
			i = strings.Index(s, "-")
		}
		if i > 0 {
			toks = append(toks[:3], s[:i], s[i:])
		} else {
			toks = append(toks, "")
		}
	}
	if len(toks) < 5 {
		return f, nil, false
	}
	dd, mm, yy, tm, tzs := toks[0], toks[1], toks[2], toks[3], toks[4]
	if dd == "" || mm == "" || yy == "" {
		return f, nil, false
	}
	mm = strings.ToLower(mm)
	if index(monthNames, mm) < 0 {
		dd, mm = mm, strings.ToLower(dd)
		if index(monthNames, mm) < 0 {
			return f, nil, false
		}
	}
	mon := index(monthNames, mm) + 1
	if mon > 12 {
		mon -= 12
	}
	if lastIs(dd, ',') {
		dd = dd[:len(dd)-1]
	}
	if i := strings.Index(yy, ":"); i > 0 {
		yy, tm = tm, yy
	}
	if yy == "" {
		return f, nil, false // yy[-1] raised IndexError
	}
	if lastIs(yy, ',') {
		yy = yy[:len(yy)-1]
		if yy == "" {
			return f, nil, false
		}
	}
	if first := []rune(yy)[0]; !unicode.IsDigit(first) {
		yy, tzs = tzs, yy
	}
	if tm == "" {
		return f, nil, false
	}
	if lastIs(tm, ',') {
		tm = tm[:len(tm)-1]
	}
	parts := strings.Split(tm, ":")
	var thh, tmm, tss string
	switch {
	case len(parts) == 2:
		thh, tmm, tss = parts[0], parts[1], "0"
	case len(parts) == 3:
		thh, tmm, tss = parts[0], parts[1], parts[2]
	case len(parts) == 1 && strings.Contains(parts[0], "."):
		parts = strings.Split(parts[0], ".")
		switch len(parts) {
		case 2:
			thh, tmm, tss = parts[0], parts[1], "0"
		case 3:
			thh, tmm, tss = parts[0], parts[1], parts[2]
		default:
			return f, nil, false
		}
	default:
		return f, nil, false
	}
	var vals [5]int
	for i, s := range []string{yy, dd, thh, tmm, tss} {
		v, good := pyInt(s)
		if !good {
			return f, nil, false
		}
		vals[i] = v
	}
	year := vals[0]
	if year < 100 {
		if year > 68 {
			year += 1900
		} else {
			year += 2000
		}
	}
	var off *int
	tzu := strings.ToUpper(tzs)
	if v, known := timezones[tzu]; known {
		off = &v
	} else if v, good := pyInt(tzu); good {
		off = &v
		if v == 0 && strings.HasPrefix(tzu, "-") {
			off = nil
		}
	}
	if off != nil && *off != 0 {
		v, sign := *off, 1
		if v < 0 {
			sign, v = -1, -v
		}
		v = sign * ((v/100)*3600 + (v%100)*60)
		off = &v
	}
	return [6]int{year, mon, vals[1], vals[2], vals[3], vals[4]}, off, true
}

// parsedateToDatetime is email.utils.parsedate_to_datetime, nil where it
// raised: no parse, a field out of range, or a zone of 24 hours or more.
func parsedateToDatetime(data string) *pdt {
	f, tz, ok := parsedateTZ(data)
	if !ok {
		return nil
	}
	t := pdt{y: f[0], mo: f[1], d: f[2], h: f[3], mi: f[4], s: f[5]}
	if !t.valid() {
		return nil
	}
	if tz != nil {
		if *tz <= -86400 || *tz >= 86400 {
			return nil
		}
		t.hasTZ, t.off = true, int64(*tz)*1e6
	}
	return &t
}

// ---- datetime.fromisoformat (Python 3.11 and later) ----

func asciiDigit(r rune) bool { return r >= '0' && r <= '9' }

func isASCII(r []rune) bool {
	for _, c := range r {
		if c > 0x7f {
			return false
		}
	}
	return true
}

type isoErr struct{}

// component is _read_isoformat_component: exactly n ASCII digits.
func component(r []rune, n int) int {
	if len(r) != n {
		panic(isoErr{})
	}
	v := 0
	for _, c := range r {
		if !asciiDigit(c) {
			panic(isoErr{})
		}
		v = v*10 + int(c-'0')
	}
	return v
}

func sub(r []rune, a, b int) []rune {
	if a > len(r) {
		a = len(r)
	}
	if b > len(r) {
		b = len(r)
	}
	if a > b {
		return nil
	}
	return r[a:b]
}

func separator(s []rune) int {
	n := len(s)
	if n == 7 {
		return 7
	}
	if s[4] == '-' {
		if s[5] == 'W' {
			if n > 8 && s[8] == '-' {
				if n == 9 {
					panic(isoErr{})
				}
				if n > 10 && asciiDigit(s[10]) {
					return 8
				}
				return 10
			}
			return 8
		}
		return 10
	}
	if s[4] == 'W' {
		idx := 7
		for idx < n && asciiDigit(s[idx]) {
			idx++
		}
		if idx < 9 {
			return idx
		}
		if idx%2 == 0 {
			return 7
		}
		return 8
	}
	return 8
}

// ordinal is _ymd2ord: day 1 is 0001-01-01.
func ordinal(y, m, d int) int {
	t := time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC)
	return int((t.Unix()-time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC).Unix())/86400) + 1
}

func isLeap(y int) bool { return y%4 == 0 && (y%100 != 0 || y%400 == 0) }

func isoweekToGregorian(year, week, day int) [3]int {
	if year < 1 || year > 9999 {
		panic(isoErr{})
	}
	if week <= 0 || week >= 53 {
		bad := true
		if week == 53 {
			first := ordinal(year, 1, 1) % 7
			if first == 4 || (first == 3 && isLeap(year)) {
				bad = false
			}
		}
		if bad {
			panic(isoErr{})
		}
	}
	if day <= 0 || day >= 8 {
		panic(isoErr{})
	}
	first := ordinal(year, 1, 1)
	wd := (first + 6) % 7
	monday := first - wd
	if wd > 3 {
		monday += 7
	}
	t := time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, monday+(week-1)*7+(day-1)-1)
	return [3]int{t.Year(), int(t.Month()), t.Day()}
}

func isoDate(s []rune) [3]int {
	if n := len(s); n != 7 && n != 8 && n != 10 {
		panic(isoErr{})
	}
	if !isASCII(s) {
		panic(isoErr{})
	}
	year := component(s[0:4], 4)
	hasSep := s[4] == '-'
	pos := 4
	if hasSep {
		pos++
	}
	if string(sub(s, pos, pos+1)) == "W" {
		pos++
		week := component(sub(s, pos, pos+2), 2)
		pos += 2
		day := 1
		if len(s) > pos {
			if (string(sub(s, pos, pos+1)) == "-") != hasSep {
				panic(isoErr{})
			}
			if hasSep {
				pos++
			}
			day = component(sub(s, pos, pos+1), 1)
		}
		return isoweekToGregorian(year, week, day)
	}
	month := component(sub(s, pos, pos+2), 2)
	pos += 2
	if (string(sub(s, pos, pos+1)) == "-") != hasSep {
		panic(isoErr{})
	}
	if hasSep {
		pos++
	}
	return [3]int{year, month, component(sub(s, pos, pos+2), 2)}
}

var fractionCorrection = []int{100000, 10000, 1000, 100, 10}

func hhmmssff(t []rune) [4]int {
	var c [4]int
	pos := 0
	hasSep := false
	for comp := 0; comp < 3; comp++ {
		c[comp] = component(sub(t, pos, pos+2), 2)
		pos += 2
		next := sub(t, pos, pos+1)
		if comp == 0 {
			hasSep = string(next) == ":"
		}
		if len(next) == 0 || comp >= 2 {
			break
		}
		if hasSep && string(next) != ":" {
			panic(isoErr{})
		}
		if hasSep {
			pos++
		}
	}
	if pos < len(t) {
		if t[pos] != '.' && t[pos] != ',' {
			panic(isoErr{})
		}
		pos++
		rest := t[pos:]
		if len(rest) == 0 {
			panic(isoErr{})
		}
		for _, r := range rest {
			if !asciiDigit(r) {
				panic(isoErr{})
			}
		}
		n := len(rest)
		if n > 6 {
			n = 6
		}
		v := 0
		for _, r := range rest[:n] {
			v = v*10 + int(r-'0')
		}
		if n < 6 {
			v *= fractionCorrection[n-1]
		}
		c[3] = v
	}
	return c
}

func find(r []rune, c rune) int {
	for i, x := range r {
		if x == c {
			return i
		}
	}
	return -1
}

type isoTime struct {
	c                      [4]int
	hasTZ                  bool
	off                    int64
	nextDay, badComp, badZ bool
}

func isoTimeOf(t []rune) isoTime {
	if len(t) < 2 || !isASCII(t) {
		panic(isoErr{})
	}
	tzPos := find(t, '-') + 1
	if tzPos == 0 {
		tzPos = find(t, '+') + 1
	}
	if tzPos == 0 {
		tzPos = find(t, 'Z') + 1
	}
	timestr := t
	if tzPos > 0 {
		timestr = t[:tzPos-1]
	}
	out := isoTime{c: hhmmssff(timestr)}
	if out.c[0] == 24 {
		if out.c[1] == 0 && out.c[2] == 0 && out.c[3] == 0 {
			out.c[0] = 0
			out.nextDay = true
		} else {
			out.badComp = true
		}
	}
	switch {
	case tzPos == len(t) && t[len(t)-1] == 'Z':
		out.hasTZ = true
	case tzPos > 0:
		tzs := t[tzPos:]
		if n := len(tzs); n == 0 || n == 1 || n == 3 || t[tzPos-1] == 'Z' {
			panic(isoErr{})
		}
		z := hhmmssff(tzs)
		if z == [4]int{} {
			out.hasTZ = true
			break
		}
		if z[0] > 23 || z[1] > 59 || z[2] > 59 || z[3] > 999999 {
			out.badZ = true
			break
		}
		off := (int64(z[0])*3600+int64(z[1])*60+int64(z[2]))*1e6 + int64(z[3])
		if t[tzPos-1] == '-' {
			off = -off
		}
		out.hasTZ, out.off = true, off
	}
	return out
}

// fromisoformat is datetime.fromisoformat, nil where it raised.
func fromisoformat(s string) (res *pdt) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(isoErr); !ok {
				panic(r)
			}
			res = nil
		}
	}()
	r := []rune(s)
	if len(r) < 7 {
		return nil
	}
	loc := separator(r)
	date := isoDate(sub(r, 0, loc))
	tstr := sub(r, loc+1, len(r))
	t := pdt{y: date[0], mo: date[1], d: date[2]}
	if len(tstr) > 0 {
		it := isoTimeOf(tstr)
		if it.badZ || it.badComp {
			return nil
		}
		if it.nextDay && t.mo >= 1 && t.mo <= 12 && t.d <= daysIn(t.y, t.mo) {
			t.d++
			if t.d > daysIn(t.y, t.mo) {
				t.d = 1
				t.mo++
				if t.mo > 12 {
					t.mo = 1
					t.y++
				}
			}
		}
		t.h, t.mi, t.s, t.us = it.c[0], it.c[1], it.c[2], it.c[3]
		t.hasTZ, t.off = it.hasTZ, it.off
	}
	if !t.valid() {
		return nil
	}
	return &t
}
