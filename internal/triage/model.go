package triage

// THE MODEL CALL
//
// One `claude -p` run, the same lock-down the supplier lane uses: no tools,
// no MCP servers, no session file, only project settings, run from an empty
// directory. The advisory goes in on stdin as data; the standing
// instructions are the system prompt. The answer comes back as the CLI's
// JSON envelope, which also carries what the call cost, so every call's
// tokens are reported - the operator asked to watch them.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/redact"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

// ModelCall says how to run the model.
type ModelCall struct {
	Bin          string        // the claude CLI
	Model        string        // e.g. a Sonnet model ID; required
	Instructions string        // the system prompt
	Timeout      time.Duration // 0 = 3 minutes
	MaxInput     int           // refuse inputs larger than this many bytes; 0 = 64 KiB
}

// Usage is what one call cost.
type Usage struct {
	InputTokens  int     `json:"input_tokens"`
	OutputTokens int     `json:"output_tokens"`
	CacheRead    int     `json:"cache_read_input_tokens"`
	CacheWrite   int     `json:"cache_creation_input_tokens"`
	CostUSD      float64 `json:"cost_usd"`
}

func (u Usage) String() string {
	return fmt.Sprintf("%d in, %d out, %d cache read, %d cache write tokens, $%.4f",
		u.InputTokens, u.OutputTokens, u.CacheRead, u.CacheWrite, u.CostUSD)
}

// envelope is the part of `claude -p --output-format json` this code reads.
type envelope struct {
	IsError bool    `json:"is_error"`
	Result  string  `json:"result"`
	Cost    float64 `json:"total_cost_usd"`
	Usage   struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
		CacheRead    int `json:"cache_read_input_tokens"`
		CacheWrite   int `json:"cache_creation_input_tokens"`
	} `json:"usage"`
}

// Run makes one call. The usage is returned even when the answer is an
// error, because an error is still billed.
func (m ModelCall) Run(ctx context.Context, input string) (string, Usage, error) {
	var u Usage
	if strings.TrimSpace(m.Model) == "" {
		return "", u, errors.New("no model set (TRIAGE_MODEL)")
	}
	if strings.TrimSpace(m.Instructions) == "" {
		return "", u, errors.New("the instructions are empty")
	}
	// The one place anything leaves for the model, so the one place redaction
	// is applied, whichever caller (reader, judge, a future one) built the
	// input. Strict, not Sensitive: only what checks itself (a formatted tax
	// id, a valid IBAN, a Luhn-valid card number), so the CVE ids, hashes, IP
	// lists and versions an advisory is made of are never rewritten. Code has
	// already extracted indicators from the raw text; this only changes what is
	// shown.
	input = redact.Strict(input)
	max := m.MaxInput
	if max <= 0 {
		max = 64 << 10
	}
	if len(input) > max {
		return "", u, fmt.Errorf("input is %d bytes, over the %d-byte cap", len(input), max)
	}
	bin := m.Bin
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("claude"); err != nil {
			return "", u, errors.New("the claude CLI was not found (set CLAUDE_BIN)")
		}
	}
	timeout := m.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	// An empty working directory: nothing for the CLI to pick up as project
	// context, and nothing to read if it ever could.
	dir, err := os.MkdirTemp("", "cti-triage-")
	if err != nil {
		return "", u, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// "--flag=value", so a model ID or instructions starting with "-" can
	// never be read as another flag.
	// #nosec G204 -- bin is CLAUDE_BIN or the PATH's claude; every argument is fixed but the model ID and the instructions, each one argv entry, never through a shell.
	// --tools stays two arguments with an empty value: the form the supplier
	// lane uses and the CLI documents. A misread "--tools=" would mean the
	// default tool set, and that is not a risk worth a shorter line.
	cmd := exec.CommandContext(ctx, bin, "-p", "--model="+m.Model,
		"--tools", "", "--strict-mcp-config", "--no-session-persistence", "--setting-sources", "project",
		"--output-format", "json", "--system-prompt="+m.Instructions)
	cmd.Dir = dir
	cmd.Env = childEnv(os.Environ(), dir)
	// A killed CLI's children can hold its output open; stop waiting for
	// them shortly after the timeout instead of hanging the run.
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdin = strings.NewReader(input)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &capped{b: &out, max: 1 << 20}, &capped{b: &errb, max: 64 << 10}
	runErr := cmd.Run()

	var env envelope
	if jerr := json.Unmarshal(out.Bytes(), &env); jerr == nil {
		u = Usage{InputTokens: env.Usage.InputTokens, OutputTokens: env.Usage.OutputTokens,
			CacheRead: env.Usage.CacheRead, CacheWrite: env.Usage.CacheWrite, CostUSD: env.Cost}
	}
	switch {
	case parent.Err() != nil:
		return "", u, errors.New("the run timed out while the model was answering")
	case ctx.Err() != nil:
		return "", u, fmt.Errorf("the model did not answer within %s", timeout)
	case runErr != nil && env.Result == "":
		return "", u, fmt.Errorf("claude failed: %v: %s", runErr, safelog.LineMax(errb.String(), 200))
	case env.IsError:
		return "", u, fmt.Errorf("the model returned an error: %s", safelog.LineMax(env.Result, 200))
	case strings.TrimSpace(env.Result) == "":
		return "", u, errors.New("the model gave no answer")
	}
	return env.Result, u, nil
}

// childEnv is the only environment the CLI gets: what it needs to run and to
// authenticate, and nothing of the fleet's - no Falcon secret, no mail
// credentials. HOME is the empty working directory, so no user or service-
// account CLAUDE.md, settings or session can reach the reader (the fleet's
// home holds the orchestrator's .claude). So the CLI must authenticate with
// ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN, as the fleet's timers do.
func childEnv(parent []string, home string) []string {
	keep := map[string]bool{
		"PATH": true, "USER": true, "LOGNAME": true, "LANG": true, "LC_ALL": true, "TZ": true,
		"ANTHROPIC_API_KEY": true, "CLAUDE_CODE_OAUTH_TOKEN": true,
		"HTTPS_PROXY": true, "HTTP_PROXY": true, "NO_PROXY": true,
		"https_proxy": true, "http_proxy": true, "no_proxy": true,
		"SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "NODE_EXTRA_CA_CERTS": true,
	}
	env := []string{"HOME=" + home, "TMPDIR=" + home}
	for _, kv := range parent {
		k, _, _ := strings.Cut(kv, "=")
		if keep[k] {
			env = append(env, kv)
		}
	}
	return env
}

// capped keeps at most max bytes and drops the rest, so a runaway CLI cannot
// fill memory.
type capped struct {
	b   *bytes.Buffer
	max int
}

// Write always reports the whole write as done: a short count would make
// the copy from the CLI fail instead of quietly dropping the excess.
func (c *capped) Write(p []byte) (int, error) {
	keep := p
	if room := c.max - c.b.Len(); room <= 0 {
		keep = nil
	} else if len(keep) > room {
		keep = keep[:room]
	}
	c.b.Write(keep)
	return len(p), nil
}
