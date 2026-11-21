# shellcheck shell=bash
# Variables starting ML_ are set for the sourcing runner to read.
# shellcheck disable=SC2034
#
# model-lane.sh - what every lane that calls the model needs around the call
# (HARNESS.md, H4). Sourced by run-checkin and run-supplier.
#
# Before this, each runner carried its own copy, and they had drifted:
# run-supplier took any claude on PATH with no ownership check, did not
# validate its model name, and its scrubbed environment dropped
# ANTHROPIC_AUTH_TOKEN, so a box set up that way failed every call silently.
# One copy now, so a control added for one lane is there for the next.
#
# POLICY HERE, THE JOB IN THE RUNNER. These functions find and vet the binary,
# check the model name and the credentials, scrub the model's environment and
# start a trace. What a lane grants the model (tools, guard, settings), what
# it sends it and what it does with the answer stay in the runner.
#
# Every function prints its own explanation to stderr, prefixed with the
# caller's name, and returns non-zero; the runner decides what failing means
# (refuse the beat, or judge nothing and mark every request Unsure). None of
# them posts to the board or exits.
#
# bash 3.2 (macOS) safe: no associative arrays, empty arrays expanded with
# ${A[@]+"${A[@]}"}.

# ML_OS: macos, linux or other. The fleet runs on Linux; macOS is a
# developer's checkout, where ownership checks do not apply.
case "$(uname -s)" in
  Darwin) ML_OS="macos" ;;
  Linux)  ML_OS="linux" ;;
  *)      ML_OS="other" ;;
esac

# ml_root_owned NAME PATH... - every PATH root-owned and writable by nobody
# else, us included. A dangling symlink is refused (someone can make it real
# later); a missing path is skipped (callers check presence themselves).
# -L judges what a symlink points at: that is what gets executed.
ml_root_owned() {
  local name="$1" p owner mode
  shift
  for p in "$@"; do
    if [ -L "$p" ] && [ ! -e "$p" ]; then
      echo "$name: REFUSING to start: $p is a dangling symlink." >&2
      return 1
    fi
    [ -e "$p" ] || continue
    owner="$(stat -L -c %u "$p" 2>/dev/null || echo unknown)"
    mode="$(stat -L -c %a "$p" 2>/dev/null || echo 7777)"
    if [ "$owner" != 0 ] || [ $(( 8#$mode & 8#022 )) -ne 0 ] || [ -w "$p" ]; then
      echo "$name: REFUSING to start: $p is writable by the service" >&2
      echo "  account or not root-owned (owner uid $owner, mode $mode)." >&2
      echo "  The fleet's code must be root-owned and read-only to the service;" >&2
      echo "  reinstall with install-fedora.sh --for-real, which puts it in /opt/cti-agent." >&2
      return 1
    fi
  done
}

# ml_find_claude NAME - print the claude binary to run. CLAUDE_BIN wins when
# set (and must be executable). Otherwise, on Linux, only the system
# locations: a copy in the service account's HOME is one the account could
# replace. On macOS, the usual developer locations, then PATH.
ml_find_claude() {
  local name="$1" c
  if [ -n "${CLAUDE_BIN:-}" ]; then
    [ -x "$CLAUDE_BIN" ] && { echo "$CLAUDE_BIN"; return 0; }
    echo "$name: CLAUDE_BIN=$CLAUDE_BIN is not executable" >&2
    return 1
  fi
  if [ "$ML_OS" = "linux" ]; then
    for c in /usr/bin/claude /usr/local/bin/claude; do
      [ -x "$c" ] && { echo "$c"; return 0; }
    done
    return 1
  fi
  for c in "$HOME/.local/bin/claude" /usr/bin/claude /usr/local/bin/claude \
           /opt/homebrew/bin/claude /snap/bin/claude; do
    [ -x "$c" ] && { echo "$c"; return 0; }
  done
  c="$(command -v claude 2>/dev/null || true)"
  [ -n "$c" ] && { echo "$c"; return 0; }
  return 1
}

# ml_claude_trusted NAME PATH - on Linux the binary must be root-owned and
# not writable by us: it runs with the fleet's credentials in reach.
ml_claude_trusted() {
  [ "$ML_OS" = "linux" ] || return 0
  ml_root_owned "$1" "$2"
}

# ml_model_ok VALUE - empty (the account's default), an alias, or a full id.
# Anything else is refused rather than passed to --model: a typo there is a
# beat on a model nobody chose, or a CLI error every run.
ml_model_ok() {
  case "$1" in
    "") return 0 ;;
    haiku|sonnet|opus|fable) return 0 ;;
    claude-?*)
      case "$1" in
        *[!abcdefghijklmnopqrstuvwxyz0123456789.-]*) return 1 ;;
      esac
      return 0 ;;
  esac
  return 1
}

# ml_auth_check NAME [env-only] - at most one credential, and one that will
# reach the model. Sets ML_AUTH_VIA for the journal. Returns 1 when more than
# one is set (claude picks one, probably not the one you meant: an API key
# bills a Console balance, an OAuth token a subscription seat) and 2 when none
# will reach it.
#
# env-only is for a lane that scrubs the model's environment (ml_scrub_env):
# its HOME is an empty folder, so on Linux stored credentials in ~/.claude
# never reach the model and only a variable will. On macOS the Keychain does.
ml_auth_check() {
  local name="$1" mode="${2:-}" set="" n=0 v
  for v in ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN CLAUDE_CODE_OAUTH_TOKEN; do
    if [ -n "${!v:-}" ] || ml_has_credential "$v"; then set="$set $v"; n=$((n + 1)); fi
  done
  set="${set# }"
  if [ "$n" -gt 1 ]; then
    echo "$name: MORE THAN ONE credential is set: $set" >&2
    echo "  claude picks one, and the one it picks is probably not the one you" >&2
    echo "  meant - ANTHROPIC_API_KEY bills a Console balance, while" >&2
    echo "  CLAUDE_CODE_OAUTH_TOKEN draws on a subscription seat." >&2
    echo "  Blank all but one in ${FLEET_ENV:-fleet.env}." >&2
    ML_AUTH_VIA="$set"
    return 1
  fi
  if [ "$n" -eq 1 ]; then
    ML_AUTH_VIA="$set"
    return 0
  fi
  if [ "$ML_OS" = "macos" ] && security find-generic-password -s "Claude Code-credentials" >/dev/null 2>&1; then
    ML_AUTH_VIA="the macOS Keychain"
    return 0
  fi
  if [ "$mode" != "env-only" ] && [ "$ML_OS" != "macos" ] && \
     [ -s "${CLAUDE_CONFIG_DIR:-$HOME/.claude}/.credentials.json" ]; then
    ML_AUTH_VIA="stored credentials in ${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
    return 0
  fi
  echo "$name: claude is not authenticated for this lane." >&2
  echo "  Set one of these in ${FLEET_ENV:-fleet.env}:" >&2
  echo "    ANTHROPIC_API_KEY        Console key, billed per token" >&2
  echo "    CLAUDE_CODE_OAUTH_TOKEN  subscription token from 'claude setup-token'" >&2
  if [ "$mode" = "env-only" ]; then
    echo "  (This lane gives the model an empty HOME, so a login stored in" >&2
    echo "  ~/.claude does not reach it: one of the variables is needed.)" >&2
  else
    echo "  or, if this account has a login shell, authenticate it once:" >&2
    echo "    sudo -u $(id -un) HOME=$HOME claude" >&2
  fi
  ML_AUTH_VIA=""
  return 2
}

# ml_scrub_env HOME - for a model call with no tools: unset every exported
# variable but what the CLI needs to run and authenticate, and point HOME and
# TMPDIR at an empty folder, so no fleet secret, user CLAUDE.md, settings or
# session reaches the model. Unset rather than `env -i KEY=...`, which would
# put the key on the command line where ps shows it. Run it in the subshell
# that starts claude, never in the runner itself.
ML_ENV_KEEP=" PATH USER LOGNAME LANG LC_ALL TZ ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN CLAUDE_CODE_OAUTH_TOKEN HTTPS_PROXY HTTP_PROXY NO_PROXY https_proxy http_proxy no_proxy SSL_CERT_FILE SSL_CERT_DIR NODE_EXTRA_CA_CERTS "
ml_scrub_env() {
  local home="$1" v creds="${CREDENTIALS_DIRECTORY:-}"
  for v in $(compgen -e); do
    case "$ML_ENV_KEEP" in *" $v "*) ;; *) unset "$v" 2>/dev/null || true ;; esac
  done
  export HOME="$home" TMPDIR="$home"
  # A model token systemd provided as a credential: the CLI authenticates only
  # through its environment, so it is exported here, in the subshell that
  # starts claude, and nowhere else.
  CREDENTIALS_DIRECTORY="$creds" ml_export_model_token
}

# ml_has_credential NAME - systemd provided NAME as a credential file.
ml_has_credential() {
  local d="${CREDENTIALS_DIRECTORY:-}"
  [ -n "$d" ] && [ -f "$d/$1" ] && [ ! -L "$d/$1" ]
}

# ml_export_model_token - export each model token systemd provided as a
# credential. Call it only in the subshell that starts claude.
ml_export_model_token() {
  local v
  for v in ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN CLAUDE_CODE_OAUTH_TOKEN; do
    if ml_has_credential "$v"; then
      export "$v=$(head -c 65536 "$CREDENTIALS_DIRECTORY/$v")"
    fi
  done
}

# ml_with_model_token CMD... - run CMD with the model token exported from its
# credential, in a subshell, so the runner itself and the commands it runs
# later never hold it in their environment.
ml_with_model_token() {
  ( ml_export_model_token; exec "$@" )
}

# ml_trace_start UNIT - print a new trace file for this lane under
# $FLEET_HOME/state/traces, or nothing. Returns 1 when fleet-trace is not
# installed and 2 when it cannot initialise the directory; either way the
# lane runs without a trace (traces are best effort, never a reason to stop).
ml_trace_start() {
  local unit="$1" tool="$FLEET_CODE/bin/fleet-trace" t
  [ -x "$tool" ] || return 1
  "$tool" init >/dev/null 2>&1 || return 2
  t="$FLEET_HOME/state/traces/$unit-$(date '+%Y%m%dT%H%M%S').jsonl"
  [ -e "$t" ] && t="${t%.jsonl}-$$.jsonl"
  echo "$t"
}

# ml_timeout SECS - set ML_TIMEOUT to a command prefix that stops a call
# after SECS, or empty where timeout(1) is not installed.
ml_timeout() {
  ML_TIMEOUT=()
  if command -v timeout >/dev/null 2>&1; then ML_TIMEOUT=(timeout "$1"); fi
}
