# bash completion for cti-agent-settings. Installed by install-fedora.sh as its
# own file (bash-completion loads a completion by the command's name). Works as
# `sudo cti-agent-settings <TAB>`.
#
# Not a fleet command (it runs as root, not through the cti-agent wrapper), so
# it is not in the command manifest; a test (test_lanes.py, SbinTools) fails
# when these subcommands and flags differ from the tool's own.
#
# `split` needs exactly one of its two modes; once one is given, nothing more.
_cti_agent_settings() {
  local cur="${COMP_WORDS[COMP_CWORD]}" sub="" i
  COMPREPLY=()
  for ((i = 1; i < COMP_CWORD; i++)); do
    case "${COMP_WORDS[i]}" in
      status|split) sub="${COMP_WORDS[i]}" ;;
      --dry-run|--for-real) return 0 ;;
    esac
  done
  case "$sub" in
    '') mapfile -t COMPREPLY < <(compgen -W "status split" -- "$cur") ;;
    split) mapfile -t COMPREPLY < <(compgen -W "--dry-run --for-real" -- "$cur") ;;
  esac
}
complete -F _cti_agent_settings cti-agent-settings
