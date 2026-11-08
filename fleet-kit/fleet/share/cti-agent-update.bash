# bash completion for cti-agent-update. Installed by install-fedora.sh as its
# own file, because bash-completion loads a completion by the command's name.
# Works as `cti-agent-update <TAB>` and `sudo cti-agent-update <TAB>`.
#
# The updater is not a fleet command (the cti-agent wrapper does not run it), so
# it is not in the command manifest. Its two flags are listed here instead, and
# a test (test_update.py) fails when they differ from update-fedora.sh.
#
# Exactly one is required. Once one is on the line there is nothing more to
# offer. Tagged like cti-agent's own completion, since bash cannot colour.
_cti_agent_update() {
  local cur="${COMP_WORDS[COMP_CWORD]}" w i
  COMPREPLY=()
  for ((i = 1; i < COMP_CWORD; i++)); do
    case "${COMP_WORDS[i]}" in --dry-run|--for-real) return 0 ;; esac
  done
  local -a words=(--dry-run --for-real)
  local -a tags=("REQUIRED, one of; read-only" "REQUIRED, one of; CHANGES THINGS")
  local -a descs=("fetch and show what is incoming, change nothing"
                  "pull the kit, then run the installer from it")
  local -a hit=()
  for ((i = 0; i < ${#words[@]}; i++)); do
    case "${words[i]}" in "$cur"*) hit+=("$i") ;; esac
  done
  COMPREPLY=()
  case "${#hit[@]}" in
    0) return 0 ;;
    1) COMPREPLY=("${words[hit[0]]}"); return 0 ;;
  esac
  compopt -o nosort 2>/dev/null || true
  if [ "${COMP_TYPE:-9}" = 63 ] || [ "${COMP_TYPE:-9}" = 33 ]; then
    printf '\nsay how to run it: exactly ONE of these:\n' >&2
  fi
  for i in "${hit[@]}"; do
    printf -v w '%-10s  %-31s  %s' "${words[i]}" "${tags[i]}" "${descs[i]}"
    COMPREPLY+=("$w")
  done
}
complete -F _cti_agent_update cti-agent-update
