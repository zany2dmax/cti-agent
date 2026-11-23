package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/zany2dmax/cti-agent/internal/pyjson"
)

func toolSummary(inp any) string {
	o, ok := inp.(obj)
	if !ok {
		return ""
	}
	for _, key := range []string{"command", "file_path", "path", "pattern", "skill", "url", "query"} {
		if o.Has(key) {
			return str(o.Get(key))
		}
	}
	return strings.Join(sortedKeys(o), ",")
}

const redactedType = "fleet_trace_redacted"

// chars is the characters one content block stands for (a redacted block
// remembers).
func chars(c obj) int {
	if c.Get("type") == redactedType {
		n := c.Get("chars")
		if b, ok := n.(bool); ok {
			if b {
				return 1
			}
			return 0
		}
		if isInt(n) && num(n) >= 0 {
			v, _ := strconv.Atoi(string(n.(jsonNumber)))
			return v
		}
		return 0
	}
	return len([]rune(str(or(c.Get("text"), ""))))
}

func resultSize(content any) int {
	switch x := content.(type) {
	case string:
		return len([]rune(x))
	case []any:
		n := 0
		for _, c := range x {
			if o, ok := c.(obj); ok {
				n += chars(o)
			}
		}
		return n
	}
	return 0
}

func resultText(content any) string {
	switch x := content.(type) {
	case string:
		return x
	case []any:
		var out []string
		for _, c := range x {
			o, ok := c.(obj)
			if !ok {
				continue
			}
			if o.Get("type") == redactedType {
				out = append(out, fmt.Sprintf("[content not kept: %d chars, sha256 %s]", chars(o), clean(o.Get("sha256"), 16, true)))
			} else {
				out = append(out, str(or(o.Get("text"), "")))
			}
		}
		return strings.Join(out, "\n")
	}
	return ""
}

// redacted is what stands in for content the trace does not keep: its size,
// and a short hash, so two traces can be told to have seen the same thing.
func redacted(text string) obj {
	o := pyjson.NewObject()
	o.Set("type", redactedType)
	o.Set("chars", jsonNumber(strconv.Itoa(len([]rune(text)))))
	o.Set("sha256", sha16(text))
	return o
}

func stub(v any) obj {
	return redacted(pyjson.Dumps(v, pyjson.Options{SortKeys: true}))
}

// What the default trace keeps, by allowlist: everything else in an event is
// replaced by its size and a short hash, so a shape this code has not seen
// is not kept by default.
var (
	keepTop  = []string{"type", "subtype", "uuid", "session_id", "parent_tool_use_id", "timestamp", "isSidechain", "is_api_error_message", "error"}
	keepMsg  = []string{"role", "model", "id", "stop_reason", "usage"}
	keepInit = []string{"model", "tools", "mcp_servers", "permissionMode", "apiKeySource", "claude_code_version", "cwd"}
)

func pick(src obj, keys []string, dst obj) obj {
	if dst == nil {
		dst = pyjson.NewObject()
	}
	for _, k := range keys {
		if src.Has(k) {
			dst.Set(k, src.Get(k))
		}
	}
	return dst
}

func without(src obj, drop ...string) obj {
	out := pyjson.NewObject()
	skip := map[string]bool{}
	for _, d := range drop {
		skip[d] = true
	}
	for _, k := range src.Keys {
		if !skip[k] {
			out.Set(k, src.Get(k))
		}
	}
	return out
}

func block(b any, etype string) any {
	o, ok := b.(obj)
	if !ok {
		return stub(b)
	}
	kind := o.Get("type")
	switch {
	case etype == "user" && kind == "tool_result":
		text := resultText(o.Get("content"))
		kept := pick(o, []string{"type", "tool_use_id"}, nil)
		// A refusal's reason is what an operator needs; a success's content
		// is somebody's mail. Only an is_error of exactly true counts.
		if v, ok := o.Get("is_error").(bool); ok && v {
			kept.Set("is_error", true)
			kept.Set("content", clean(text, 300, true))
		} else {
			kept.Set("is_error", false)
			kept.Set("content", []any{redacted(text)})
		}
		return kept
	case etype == "assistant" && kind == "text":
		out := pyjson.NewObject()
		out.Set("type", "text")
		t, _ := o.Get("text").(string)
		out.Set("text", t)
		return out
	case etype == "assistant" && kind == "tool_use":
		return pick(o, []string{"type", "id", "name", "input"}, nil)
	}
	out := stub(o)
	was := "unknown"
	if s, ok := kind.(string); ok {
		was = s
	}
	out.Set("was", was)
	return out
}

// minimize is the event as the default trace keeps it: the decision and the
// cost, not the content the beat read.
func minimize(ev obj) obj {
	etype := ev.Get("type")
	switch etype {
	case "result", "fleet_trace", "fleet_trace_text":
		return ev
	case "system":
		keep := pick(ev, keepTop, nil)
		if ev.Get("subtype") == "init" {
			pick(ev, keepInit, keep)
		} else {
			keep.Set("detail", stub(without(ev, keepTop...)))
		}
		return keep
	case "user", "assistant":
		out := pick(ev, keepTop, nil)
		if msg, ok := ev.Get("message").(obj); ok {
			m := pick(msg, keepMsg, nil)
			switch c := msg.Get("content").(type) {
			case []any:
				blocks := make([]any, len(c))
				for i, b := range c {
					blocks[i] = block(b, etype.(string))
				}
				m.Set("content", blocks)
			case nil:
			default:
				m.Set("content", []any{stub(c)})
			}
			out.Set("message", m)
		}
		if extra := without(ev, append(append([]string{}, keepTop...), "message")...); extra.Len() > 0 {
			out.Set("extra", stub(extra))
		}
		return out
	}
	out := pyjson.NewObject()
	t := "unknown"
	if s, ok := etype.(string); ok {
		t = s
	}
	out.Set("type", t)
	out.Set("detail", stub(ev))
	return out
}

// timeline turns events into lines a person reads. Tool results show as a
// size and ok/ERROR, not their content: that is untrusted text, and the
// journal is read by more people than the trace. full prints it, cleaned.
type timeline struct {
	out   io.Writer
	full  bool
	turn  int
	tools map[string]string
}

func newTimeline(out io.Writer, full bool) *timeline {
	return &timeline{out: out, full: full, tools: map[string]string{}}
}

func (t *timeline) line(s string) { _, _ = fmt.Fprintf(t.out, "[trace] %s\n", s) }

func fmt0(v float64) string { return strconv.FormatFloat(v, 'f', 0, 64) }

func (t *timeline) event(ev obj) {
	switch ev.Get("type") {
	case "fleet_trace":
		if truthy(ev.Get("truncated")) {
			t.line(fmt.Sprintf("trace truncated at %s bytes; the beat went on", str(ev.Get("max_bytes"))))
		}
		return
	case "fleet_trace_text":
		t.line("stderr: " + clean(ev.Get("text"), 300, true))
		return
	case "system":
		if ev.Get("subtype") != "init" {
			return
		}
		mcp := or(ev.Get("mcp_servers"), []any{})
		t.line(fmt.Sprintf("start: model %s, %d tools, %d MCP servers, permission mode %s, auth %s, claude %s",
			clean(ev.Get("model"), -1, true), length(or(ev.Get("tools"), []any{})), length(mcp),
			clean(ev.Get("permissionMode"), -1, true), clean(ev.Get("apiKeySource"), -1, true),
			clean(ev.Get("claude_code_version"), -1, true)))
		return
	case "assistant":
		msgV := or(ev.Get("message"), nil)
		if truthy(ev.Get("is_api_error_message")) {
			msg := dictOr(msgV)
			t.line(fmt.Sprintf("API ERROR (%s): %s", clean(ev.Get("error"), -1, true), clean(resultText(msg.Get("content")), 300, true)))
			return
		}
		t.turn++
		msg := dictOr(msgV)
		for _, b := range iter(or(msg.Get("content"), []any{})) {
			o, ok := b.(obj)
			if !ok {
				continue
			}
			switch o.Get("type") {
			case "text":
				text := ""
				if o.Has("text") {
					s, ok := o.Get("text").(string)
					if !ok {
						raise("AttributeError")
					}
					text = s
				}
				if pyStrip(text) != "" {
					t.line(fmt.Sprintf("turn %d says: %s", t.turn, clean(text, 300, true)))
				}
			case "tool_use":
				name := clean(o.Get("name"), -1, true)
				t.tools[hashKey(o.Get("id"))] = name
				t.line(fmt.Sprintf("turn %d tool %s: %s", t.turn, name, clean(toolSummary(o.Get("input")), 200, true)))
			}
		}
		return
	case "user":
		content := dictOr(ev.Get("message")).Get("content")
		list, _ := content.([]any)
		for _, b := range list {
			o, ok := b.(obj)
			if !ok || o.Get("type") != "tool_result" {
				continue
			}
			name, ok := t.tools[hashKey(o.Get("tool_use_id"))]
			if !ok {
				name = "?"
			}
			c := o.Get("content")
			if truthy(o.Get("is_error")) {
				t.line(fmt.Sprintf("  %s -> ERROR: %s", name, clean(resultText(c), 200, true)))
			} else {
				t.line(fmt.Sprintf("  %s -> ok, %d chars", name, resultSize(c)))
			}
			if t.full {
				for _, l := range splitLines(clean(resultText(c), 4000, false)) {
					_, _ = fmt.Fprintf(t.out, "        | %s\n", l)
				}
			}
		}
		return
	case "result":
		u := dictOr(ev.Get("usage"))
		denials := or(ev.Get("permission_denials"), []any{})
		status := "ok"
		if truthy(ev.Get("is_error")) {
			status = "ERROR"
		}
		reason := or(ev.Get("terminal_reason"), ev.Get("subtype"))
		d := or(ev.Get("duration_ms"), jsonNumber("0"))
		if _, ok := d.(string); ok {
			raise("TypeError")
		}
		if !isNumber(d) {
			if _, ok := d.(bool); !ok {
				raise("TypeError")
			}
		}
		s := fmt.Sprintf("end: %s (%s), %s turns, %ss, tokens in %s + cache read %s + cache write %s, out %s",
			status, clean(reason, -1, true), str(ev.Get("num_turns")), fmt0(num(d)/1000),
			str(getOr(u, "input_tokens")), str(getOr(u, "cache_read_input_tokens")),
			str(getOr(u, "cache_creation_input_tokens")), str(getOr(u, "output_tokens")))
		cost := ev.Get("total_cost_usd")
		if _, ok := cost.(bool); ok || isNumber(cost) {
			s += fmt.Sprintf(", $%s", strconv.FormatFloat(num(cost), 'f', 4, 64))
		}
		s += fmt.Sprintf(", %d denied", length(denials))
		t.line(s)
		for _, x := range iter(denials) {
			if o, ok := x.(obj); ok {
				t.line(fmt.Sprintf("  DENIED %s: %s", clean(o.Get("tool_name"), -1, true), clean(toolSummary(o.Get("tool_input")), 200, true)))
			}
		}
	}
}

// getOr is u.get(k, 0): 0 only when the key is absent.
func getOr(u obj, k string) any {
	if u.Has(k) {
		return u.Get(k)
	}
	return jsonNumber("0")
}

// plainLines is what text mode would have printed for one line: non-JSON
// lines (stderr), API error messages, and the result text. cti-budget
// classifies this, so tool output and token counts must not be in it.
func plainLines(ev obj, raw string) []string {
	if ev == nil {
		return []string{raw}
	}
	if ev.Get("type") == "assistant" && truthy(ev.Get("is_api_error_message")) {
		var out []string
		if truthy(ev.Get("error")) {
			out = append(out, "API error: "+str(ev.Get("error")))
		}
		if text := resultText(dictOr(ev.Get("message")).Get("content")); text != "" {
			out = append(out, text)
		}
		return out
	}
	if ev.Get("type") == "result" {
		if s, ok := ev.Get("result").(string); ok {
			return []string{s}
		}
	}
	return nil
}
