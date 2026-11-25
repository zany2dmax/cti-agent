# bash completion for cti-agent-onboard. Installed by install-fedora.sh as its
# own file (bash-completion loads a completion by the command's name). Works as
# `sudo cti-agent-onboard <TAB>`.
#
# Not a fleet command (it runs as root, not through the cti-agent wrapper), so
# it is not in the command manifest; a test (test_lanes.py, SbinTools) fails
# when these flags differ from the tool's own.
#
# Exactly one of --dry-run and --for-real; --lanes takes the lane names from
# the installed lane list.
_cti_agent_onboard() {
  local cur="${COMP_WORDS[COMP_CWORD]}" prev="${COMP_WORDS[COMP_CWORD-1]}" mode="" i
  COMPREPLY=()
  if [ "$prev" = --lanes ]; then
    mapfile -t COMPREPLY < <(compgen -W "$(awk -F'\t' '!/^#/ && NF {print $1}' @CODE_DIR@/share/lanes.list 2>/dev/null)" -- "${cur##*,}")
    return 0
  fi
  for ((i = 1; i < COMP_CWORD; i++)); do
    case "${COMP_WORDS[i]}" in --dry-run|--for-real) mode=1 ;; esac
  done
  if [ -n "$mode" ]; then
    mapfile -t COMPREPLY < <(compgen -W "--lanes" -- "$cur")
  else
    mapfile -t COMPREPLY < <(compgen -W "--dry-run --for-real --lanes" -- "$cur")
  fi
}
complete -F _cti_agent_onboard cti-agent-onboard
