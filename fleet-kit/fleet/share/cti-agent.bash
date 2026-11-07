# bash completion for cti-agent. Installed by install-fedora.sh with @CODE_DIR@
# filled in. Works as `cti-agent <TAB>` and `sudo cti-agent <TAB>` (sudo's own
# completion re-bases COMP_WORDS onto the command). Everything it offers comes
# from the command manifest through cti-agent-usage, so it cannot go stale.
#
# One match completes to the bare word. Several are listed with a tag and a
# description, and the tag says how risky it is, because bash cannot colour a
# completion list (readline prints escape codes as ^[):
#
#   read-only / optional; read-only     changes nothing
#   writes own files / test send        touches only the fleet's own files
#   CHANGES THINGS / CHANGES            sends, moves or files something
#   REQUIRED, one of                    say how to run it: exactly one of these
#
# The list is ordered subcommands, then REQUIRED, then optional.
_cti_agent() {
  local usage=@CODE_DIR@/share/cti-agent-usage
  [ -x "$usage" ] || return 0
  local cur="${COMP_WORDS[COMP_CWORD]}" cmd="" rows
  if [ "$COMP_CWORD" -eq 1 ]; then
    rows=$("$usage" complete 2>/dev/null)
  else
    cmd="${COMP_WORDS[1]}"
    rows=$("$usage" complete "$cmd" "$COMP_CWORD" 2>/dev/null)
  fi
  [ -n "$rows" ] || return 0

  local g w r l d s n=0 ww=0 lw=0 anyreq=""
  local words=() specs=() labels=() descs=()
  for g in command sub required optional; do
    while IFS=$'\t' read -r w gg r l d s; do
      [ "$gg" = "$g" ] || continue
      case "$w" in "$cur"*) ;; *) continue ;; esac
      words[n]="$w"; specs[n]="$s"; labels[n]="$l"; descs[n]="$d"
      [ "$g" = required ] && anyreq=1
      [ "${#s}" -gt "$ww" ] && ww=${#s}
      [ "${#l}" -gt "$lw" ] && lw=${#l}
      n=$((n + 1))
    done <<< "$rows"
  done
  [ "$n" -gt 0 ] || return 0

  COMPREPLY=()
  if [ "$n" -eq 1 ]; then
    COMPREPLY=("${words[0]}")
    return 0
  fi

  # Keep the order above where this bash can (4.4+); older ones sort.
  compopt -o nosort 2>/dev/null || true

  # A line above the list, only when the list is actually being shown (the
  # second TAB), so a first TAB that merely completes a prefix stays quiet.
  if [ "${COMP_TYPE:-9}" = 63 ] || [ "${COMP_TYPE:-9}" = 33 ]; then
    if [ -z "$cmd" ]; then
      printf '\none of these commands - read-only changes nothing, writes own files touches only the\nfleet'"'"'s own files, CHANGES THINGS sends, moves or files something:\n' >&2
    elif [ -n "$anyreq" ]; then
      printf '\nsay how to run it: exactly ONE of the REQUIRED flags; the rest are optional:\n' >&2
    fi
  fi

  local i entry
  for ((i = 0; i < n; i++)); do
    d="${descs[i]}"
    [ "${#d}" -gt 68 ] && d="${d:0:67}..."
    printf -v entry '%-*s  %-*s  %s' "$ww" "${specs[i]}" "$lw" "${labels[i]}" "$d"
    COMPREPLY[i]="$entry"
  done
}
complete -F _cti_agent cti-agent
