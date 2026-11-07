# bash completion for cti-agent. Installed by install-fedora.sh with @CODE_DIR@
# filled in. Works as `cti-agent <TAB>` and `sudo cti-agent <TAB>` (sudo's own
# completion re-bases COMP_WORDS onto the command). Everything it offers comes
# from the command manifest through cti-agent-usage, so it cannot go stale.
_cti_agent() {
  local usage=@CODE_DIR@/share/cti-agent-usage
  local cur="${COMP_WORDS[COMP_CWORD]}"
  [ -x "$usage" ] || return 0
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "$("$usage" words 2>/dev/null)" -- "$cur") )
  else
    COMPREPLY=( $(compgen -W "$("$usage" words "${COMP_WORDS[1]}" "$COMP_CWORD" 2>/dev/null)" -- "$cur") )
  fi
}
complete -F _cti_agent cti-agent
