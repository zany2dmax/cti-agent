# bash completion for cti-agent-secrets. Installed by install-fedora.sh as its
# own file (bash-completion loads a completion by the command's name), with
# @CODE_DIR@ and @CONF_DIR@ filled in. Works as `sudo cti-agent-secrets <TAB>`.
#
# Not a fleet command (it runs as root, not through the cti-agent wrapper), so
# it is not in the command manifest; a test (test_lanes.py, SbinTools) fails
# when these subcommands and flags differ from the tool's own.
#
# `set` offers the names settings.manifest marks secret or credential;
# `remove` offers the ones stored, from the names-only list the tool keeps
# (the store itself is root-only, and completion runs as you).
_cti_agent_secrets() {
  local cur="${COMP_WORDS[COMP_CWORD]}" sub="" at=0 i
  COMPREPLY=()
  for ((i = 1; i < COMP_CWORD; i++)); do
    case "${COMP_WORDS[i]}" in status|import|set|remove) sub="${COMP_WORDS[i]}"; at=$i; break ;; esac
  done
  case "$sub" in
    '') mapfile -t COMPREPLY < <(compgen -W "status import set remove" -- "$cur") ;;
    import) mapfile -t COMPREPLY < <(compgen -W "--dry-run" -- "$cur") ;;
    set)
      if [ "$COMP_CWORD" -eq $((at + 1)) ]; then
        mapfile -t COMPREPLY < <(compgen -W "$(awk '/^key: /{k=$2} /^(secret|credential): yes/{print k}' \
          @CODE_DIR@/settings.manifest 2>/dev/null | sort -u)" -- "$cur")
      fi ;;
    remove)
      if [ "$COMP_CWORD" -eq $((at + 1)) ]; then
        mapfile -t COMPREPLY < <(compgen -W "$(grep -v '^#' @CONF_DIR@/credentials.stored 2>/dev/null)" -- "$cur")
      fi ;;
  esac
}
complete -F _cti_agent_secrets cti-agent-secrets
