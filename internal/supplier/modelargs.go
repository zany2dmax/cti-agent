package supplier

// ModelArgs is the argument list for the model call: print mode, the model, NO
// tools (--tools ""), no MCP servers, no session file, and only project
// settings (the runner starts it from an empty directory, so there are none).
// The request is the standard input; the standing instructions are the system
// prompt.
//
// The runner (fleet-kit/fleet/bin/run-supplier) is bash and spells these out
// itself; this is the same list in Go so the eval harness calls the model exactly
// as production does, and a test fails if the runner stops saying any of them.
func ModelArgs(model, systemPrompt string) []string {
	return []string{
		"-p", "--model", model,
		"--tools", "",
		"--strict-mcp-config", "--no-session-persistence",
		"--setting-sources", "project",
		"--system-prompt", systemPrompt,
	}
}
