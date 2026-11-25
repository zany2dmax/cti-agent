# bash completion for cti-agent-doctor. Installed by install-fedora.sh as its
# own file (bash-completion loads a completion by the command's name). Works as
# `sudo cti-agent-doctor <TAB>`.
#
# Not a fleet command (it runs as root, not through the cti-agent wrapper), so
# it is not in the command manifest; a test (test_lanes.py, SbinTools) fails
# when these flags differ from the tool's own.
#
# Read-only: no mode to give. --json once.
_cti_agent_doctor() {
  local cur="${COMP_WORDS[COMP_CWORD]}" i
  COMPREPLY=()
  for ((i = 1; i < COMP_CWORD; i++)); do
    [ "${COMP_WORDS[i]}" = --json ] && return 0
  done
  mapfile -t COMPREPLY < <(compgen -W "--json" -- "$cur")
}
complete -F _cti_agent_doctor cti-agent-doctor
