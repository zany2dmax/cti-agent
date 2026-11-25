# shellcheck shell=bash disable=SC2034 # the layout variables are set here for the scripts that source this
# layout.sh - where this kit installs the fleet. Sourced by install-fedora.sh
# and update-fedora.sh; not installed.
#
#   layout_load KIT_ROOT        set CODE_DIR CONF_DIR STATE_DIR LOG_DIR
#                               FLEET_USER FLEET_GROUP AGENT_REPO, and
#                               LAYOUT_RELOCATED=1 when any differs from the
#                               FHS default; returns 1, saying why, on a bad file
#   layout_relocate             a filter: stdin with every default path and the
#                               default account name rewritten to the layout's
#   layout_relocate_files F...  the same, in place, for each text file given
#
# The defaults are the FHS layout every box has used: code in /opt/cti-agent,
# config in /etc/cti-agent, state in /var/lib/cti-agent, the audit trail in
# /var/log/cti-agent, the service account ctiagent, and the Go source built
# from this kit's own git remote (so a fork builds the fork). A fork that
# installs elsewhere commits a layout.env at the top of its repository, which
# upstream never ships (docs/layout.md):
#
#   LAYOUT_CODE_DIR=/srv/fleet/code
#   LAYOUT_CONF_DIR=/srv/fleet/etc
#   LAYOUT_STATE_DIR=/srv/fleet/state
#   LAYOUT_LOG_DIR=/srv/fleet/log
#   LAYOUT_USER=fleet
#   LAYOUT_REPO=https://github.com/example/cti-agent
#
# The file is READ, never sourced: it is in a checkout, and this runs as
# root. Only those keys are accepted, each is checked, and anything else stops
# the install before anything changes.
#
# HOW RELOCATION WORKS. The repository's files - units, runners, the root
# tools, the orchestrator's instructions, man pages - name the default paths,
# so they and everything generated from them stay as they are. The installer
# rewrites the installed copies (layout_relocate_files), and stamps the Go
# binaries at build time (-X .../internal/layout). One account name serves as
# both user and group: "ctiagent" appears as both in those files and cannot be
# told apart when rewriting.

LAYOUT_DEF_CODE=/opt/cti-agent
LAYOUT_DEF_CONF=/etc/cti-agent
LAYOUT_DEF_STATE=/var/lib/cti-agent
LAYOUT_DEF_LOG=/var/log/cti-agent
LAYOUT_DEF_USER=ctiagent

_layout_bad() { echo "layout.env: $*" >&2; return 1; }

_layout_path_ok() {
  local key="$1" v="$2"
  case "$v" in
    /) _layout_bad "$key=$v: not the root directory"; return 1 ;;
    /*) ;;
    *) _layout_bad "$key=$v: an absolute path, starting with /"; return 1 ;;
  esac
  if ! printf '%s' "$v" | grep -Eq '^/[A-Za-z0-9._/-]+$'; then
    _layout_bad "$key=$v: letters, digits and . _ - / only"; return 1
  fi
  case "$v" in */) _layout_bad "$key=$v: no trailing /"; return 1 ;; esac
  case "$v/" in */../*|*/./*|*//*) _layout_bad "$key=$v: no . or .. or empty parts"; return 1 ;; esac
  # The units run with ProtectHome=yes and PrivateTmp, so these are hidden or
  # emptied for every lane; and the kernel's and runtime's own trees are not
  # a place for a fleet.
  case "$v/" in
    /home/*|/root/*|/tmp/*|/var/tmp/*|/run/*|/proc/*|/sys/*|/dev/*|/boot/*)
      _layout_bad "$key=$v: not under ${v%"${v#/*/}"}, which the units hide or which is not the fleet's"; return 1 ;;
  esac
  return 0
}

layout_load() {
  local kit="$1" f="$1/layout.env" line key val n=0
  CODE_DIR=$LAYOUT_DEF_CODE CONF_DIR=$LAYOUT_DEF_CONF STATE_DIR=$LAYOUT_DEF_STATE
  LOG_DIR=$LAYOUT_DEF_LOG FLEET_USER=$LAYOUT_DEF_USER AGENT_REPO=""
  if [ -f "$f" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      n=$((n + 1))
      case "$line" in ''|'#'*) continue ;; esac
      key="${line%%=*}"; val="${line#*=}"
      [ "$key" != "$line" ] || { _layout_bad "line $n is not KEY=value"; return 1; }
      val="${val%\"}"; val="${val#\"}"
      case "$key" in
        LAYOUT_CODE_DIR)  _layout_path_ok "$key" "$val" || return 1; CODE_DIR=$val ;;
        LAYOUT_CONF_DIR)  _layout_path_ok "$key" "$val" || return 1; CONF_DIR=$val ;;
        LAYOUT_STATE_DIR) _layout_path_ok "$key" "$val" || return 1; STATE_DIR=$val ;;
        LAYOUT_LOG_DIR)   _layout_path_ok "$key" "$val" || return 1; LOG_DIR=$val ;;
        LAYOUT_USER)
          printf '%s' "$val" | grep -Eq '^[a-z_][a-z0-9_-]{0,30}$' \
            || { _layout_bad "LAYOUT_USER=$val: a lower-case account name"; return 1; }
          FLEET_USER=$val ;;
        LAYOUT_REPO)
          printf '%s' "$val" | grep -Eq '^(https://|ssh://|git@)[A-Za-z0-9._:/@~-]+$' \
            || { _layout_bad "LAYOUT_REPO=$val: an https://, ssh:// or git@ URL"; return 1; }
          AGENT_REPO=$val ;;
        *) _layout_bad "line $n: $key is not a layout setting (LAYOUT_CODE_DIR, LAYOUT_CONF_DIR, LAYOUT_STATE_DIR, LAYOUT_LOG_DIR, LAYOUT_USER, LAYOUT_REPO)"; return 1 ;;
      esac
    done < "$f"
  fi
  # No directory inside another: an uninstall or a snapshot of one would take
  # the other with it.
  local a b
  for a in "$CODE_DIR" "$CONF_DIR" "$STATE_DIR" "$LOG_DIR"; do
    for b in "$CODE_DIR" "$CONF_DIR" "$STATE_DIR" "$LOG_DIR"; do
      [ "$a" = "$b" ] && continue
      case "$b/" in "$a"/*) _layout_bad "$b is inside $a: each directory stands alone"; return 1 ;; esac
    done
  done
  # Nor a new path that holds another default path: rewriting the installed
  # files would then change it twice. (Its own default is fine: unchanged.)
  local own name def
  for own in "CODE_DIR:$LAYOUT_DEF_CODE" "CONF_DIR:$LAYOUT_DEF_CONF" "STATE_DIR:$LAYOUT_DEF_STATE" "LOG_DIR:$LAYOUT_DEF_LOG"; do
    name="${own%%:*}"; a="${!name}"; b="${own#*:}"
    [ "$a" = "$b" ] && continue
    for def in "$LAYOUT_DEF_CODE" "$LAYOUT_DEF_CONF" "$LAYOUT_DEF_STATE" "$LAYOUT_DEF_LOG"; do
      case "$a/" in "$def"/*) _layout_bad "LAYOUT_$name=$a holds the default path $def; choose one that does not"; return 1 ;; esac
    done
  done
  FLEET_GROUP=$FLEET_USER
  if [ -z "$AGENT_REPO" ]; then
    # The kit's own remote, so a fork's box builds the fork's code.
    AGENT_REPO="$(git -C "$kit" remote get-url origin 2>/dev/null || true)"
    [ -n "$AGENT_REPO" ] || AGENT_REPO=https://github.com/zany2dmax/cti-agent
  fi
  LAYOUT_RELOCATED=""
  if [ "$CODE_DIR" != "$LAYOUT_DEF_CODE" ] || [ "$CONF_DIR" != "$LAYOUT_DEF_CONF" ] \
     || [ "$STATE_DIR" != "$LAYOUT_DEF_STATE" ] || [ "$LOG_DIR" != "$LAYOUT_DEF_LOG" ] \
     || [ "$FLEET_USER" != "$LAYOUT_DEF_USER" ]; then
    LAYOUT_RELOCATED=1
  fi
  return 0
}

# A default path is replaced where it ends: followed by a character a name
# cannot continue with, a sentence's full stop, or the end of the line. So
# /opt/cti-agent/bin, "/opt/cti-agent" and "in /var/log/cti-agent." change,
# and /var/lib/cti-agent-update and /opt/cti-agent.next do not.
layout_relocate() {
  if [ -z "${LAYOUT_RELOCATED:-}" ]; then cat; return; fi
  # In a unit: StateDirectory=/LogsDirectory= always mean /var/lib and
  # /var/log, so for a state or log directory elsewhere the unit grants that
  # directory with ReadWritePaths= instead (ProtectSystem=strict makes the rest
  # read-only), and systemd no longer makes the /var one.
  local units=()
  if [ "$STATE_DIR" != "$LAYOUT_DEF_STATE" ]; then
    units+=(-e "s#^StateDirectory=cti-agent\$#ReadWritePaths=${STATE_DIR}#" -e "/^StateDirectoryMode=/d")
  fi
  if [ "$LOG_DIR" != "$LAYOUT_DEF_LOG" ]; then
    units+=(-e "s#^LogsDirectory=cti-agent\$#ReadWritePaths=${LOG_DIR}#" -e "/^LogsDirectoryMode=/d")
  fi
  sed -E ${units[@]+"${units[@]}"} \
    -e "s#${LAYOUT_DEF_STATE}(\\.?([^A-Za-z0-9_.-]|\$))#${STATE_DIR}\\1#g" \
    -e "s#${LAYOUT_DEF_LOG}(\\.?([^A-Za-z0-9_.-]|\$))#${LOG_DIR}\\1#g" \
    -e "s#${LAYOUT_DEF_CONF}(\\.?([^A-Za-z0-9_.-]|\$))#${CONF_DIR}\\1#g" \
    -e "s#${LAYOUT_DEF_CODE}(\\.?([^A-Za-z0-9_.-]|\$))#${CODE_DIR}\\1#g" \
    -e "s#(^|[^A-Za-z0-9_-])${LAYOUT_DEF_USER}([^A-Za-z0-9_-]|\$)#\\1${FLEET_USER}\\2#g" \
    -e "s#(^|[^A-Za-z0-9_-])${LAYOUT_DEF_USER}([^A-Za-z0-9_-]|\$)#\\1${FLEET_USER}\\2#g"
}

layout_relocate_files() {
  [ -n "${LAYOUT_RELOCATED:-}" ] || return 0
  local f tmp
  for f in "$@"; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    grep -Iq . "$f" 2>/dev/null || continue   # binaries and empty files as they are
    tmp="$(mktemp "${f%/*}/.relocate.XXXXXX")"
    layout_relocate < "$f" > "$tmp"
    if cmp -s "$f" "$tmp"; then rm -f "$tmp"; continue; fi
    chmod --reference="$f" "$tmp" 2>/dev/null || chmod "$(stat -f '%Lp' "$f")" "$tmp"
    chown --reference="$f" "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$f"
  done
}
