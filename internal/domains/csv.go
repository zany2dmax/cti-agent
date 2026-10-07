package domains

import (
	"bytes"
	"encoding/csv"
	"sort"
	"strconv"
	"strings"
)

// CSVHeader is sitecheck.go's column set, in its order, followed by what this
// lane adds. The original columns come first and keep their names so a
// spreadsheet or script built on the old output still lines up.
var CSVHeader = []string{
	// sitecheck.go
	"domain",
	"dns_ok", "has_a", "has_aaaa", "cname",
	"has_mx", "mx_hosts",
	"has_spf", "spf_record",
	"has_dmarc", "dmarc_record",
	"has_dkim", "dkim_selectors", "dkim_records",
	"smtp_checked", "smtp_host", "smtp_port", "smtp_banner",
	"scheme", "status", "active", "final_url", "response_time_ms",
	"tls_server_name", "tls_issuer",
	"error", "excluded_parked",
	"email_check_note",
	// added by this lane
	"inventory_domain", "role", "registrar_hosted", "parked_indicator", "title",
	"https_status", "http_status", "hsts", "server",
	"tls_verified", "tls_verify_error", "tls_not_after", "tls_dns_names",
	"dangling_cname", "mx_unresolved", "smtp_starttls", "smtp_error",
	"dkim_bits", "dmarc_policy", "dmarc_rua", "spf_lookups",
}

// CSV renders one row per probed host: the inventory name and, for an apex,
// its www. Mail columns describe the inventory name and repeat on its www row
// so every row stands alone when filtered.
func CSV(results []Result) []byte {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write(CSVHeader)
	for _, r := range sortedResults(results) {
		for _, web := range r.Web {
			row := csvRow(r, web)
			for i := range row {
				row[i] = cell(row[i])
			}
			_ = w.Write(row)
		}
	}
	w.Flush()
	return buf.Bytes()
}

func boolStr(v bool) string { return strconv.FormatBool(v) }

// cell neutralises spreadsheet formula injection. Page titles, banners and
// TXT records are written by whoever controls the remote end, and a cell
// starting with = + - or @ is executed by Excel when the CSV is opened.
func cell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func csvRow(r Result, w Web) []string {
	m := r.Mail
	best := w.Best()
	scheme := ""
	switch {
	case best.OK() && strings.HasPrefix(best.FinalURL, "https"):
		scheme = "https"
	case best.OK():
		scheme = "http"
	}
	errText := firstNonEmptyStr(w.Addrs.Err, best.Err)

	mxHosts := strings.Join(m.MX.Values, ";")
	note := ""
	switch {
	case !m.MX.Known():
		note = "MX lookup failed: " + m.MX.Err
	case !m.SPF.Known():
		note = "SPF lookup failed: " + m.SPF.Err
	case !m.DMARC.Known():
		note = "DMARC lookup failed: " + m.DMARC.Err
	}

	var dkimRecs, dkimBits []string
	sels := append([]string(nil), m.DKIM.Found...)
	sort.Strings(sels)
	for _, s := range sels {
		dkimRecs = append(dkimRecs, m.DKIM.Records[s])
		dkimBits = append(dkimBits, s+"="+strconv.Itoa(m.DKIM.Bits[s]))
	}

	pol, rua := "", ""
	if len(m.DMARC.Values) == 1 {
		d := ParseDMARC(m.DMARC.Values[0])
		pol = d.Effective(m.DMARCFrom != r.Entry.Name)
		rua = strings.Join(d.RUA, ";")
	}

	notAfter := ""
	if !w.TLS.NotAfter.IsZero() {
		notAfter = w.TLS.NotAfter.Format("2006-01-02")
	}
	status := func(f Fetch) string {
		if !f.OK() {
			return ""
		}
		return strconv.Itoa(f.Status)
	}

	return []string{
		w.Host,
		boolStr(w.Addrs.Present()), boolStr(w.HasA), boolStr(w.HasAAAA), w.CNAME,
		boolStr(m.MX.Present()), mxHosts,
		boolStr(len(m.SPF.Values) > 0), strings.Join(m.SPF.Values, " || "),
		boolStr(len(m.DMARC.Values) > 0), strings.Join(m.DMARC.Values, " || "),
		boolStr(len(m.DKIM.Found) > 0), strings.Join(sels, ";"), strings.Join(dkimRecs, " || "),
		boolStr(m.SMTP.Checked), m.SMTP.Host, portText(m.SMTP), m.SMTP.Banner,
		scheme, status(best), boolStr(w.Live()), best.FinalURL, strconv.FormatInt(best.Elapsed.Milliseconds(), 10),
		w.Host, w.TLS.Issuer,
		errText, boolStr(w.ParkedBy() != ""),
		note,
		r.Entry.Name, role(r.Entry), w.RegistrarPage(), w.ParkedBy(), best.Title,
		status(w.HTTPS), status(w.HTTP), boolStr(w.HTTPS.HSTS), best.Server,
		boolStr(w.TLS.Verified), firstNonEmptyStr(w.TLS.VerifyErr, w.TLS.DialErr), notAfter,
		strings.Join(w.TLS.Names, ";"),
		boolStr(w.Dangling), strings.Join(m.MXUnresolved, ";"), boolStr(m.SMTP.StartTLS), m.SMTP.Err,
		strings.Join(dkimBits, ";"), pol, rua, strconv.Itoa(m.SPFLookups),
	}
}

func portText(s SMTPResult) string {
	if !s.Checked {
		return ""
	}
	return strconv.Itoa(s.Port)
}

func firstNonEmptyStr(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
