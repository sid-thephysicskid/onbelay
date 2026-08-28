#!/usr/bin/env bash
# Rename pre-0.4.0 (`agent-config`) install state to its current spelling.
#
# The rename to On Belay changed every marker install uses to recognize its own
# work. Nothing about their meaning changed, only the name, so renaming them
# here means the rest of the installer sees an ordinary install. Teaching each
# call site a second spelling instead would put "is this ours" in seven places
# permanently.
#
# Symlinks and the payload root are deliberately NOT touched: migrating the
# origins file is enough, because that is what ownership is decided from, and
# the normal relink path then adopts every link on its own.
#
# Usage: migrate-legacy.sh <claude root> <codex root> [--check]
# Prints one line per change. Silent, exit 0, on a machine that never ran 0.3.x.
set -uo pipefail
C="$1"; X="$2"; CHECK=0; [[ "${3:-}" == --check ]] && CHECK=1

# The origins file is a list of paths, so both lists have to survive; a
# duplicate line is harmless because the reader stops at the first match. The
# two backups are whole files, and if the current name already exists the
# legacy one is a leftover from a half-finished upgrade, not a second source.
move() {  # move <legacy> <current> <append|discard>
  [[ -e "$1" ]] || return 0
  if (( ! CHECK )); then
    if [[ -e "$2" ]]; then
      [[ "$3" == append ]] && cat "$1" >> "$2"
      rm -f "$1"
    else
      mv "$1" "$2"
    fi
  fi
  echo "moved $(basename "$1")"
}

# A literal swap of a marker that appears nowhere else, rather than a JSON
# round-trip: it cannot reformat the rest of someone's config, and `cat >`
# writes THROUGH a symlink a dotfile manager may have put here.
retag() {  # retag <file>
  local t
  [[ -f "$1" ]] && grep -q 'agent-config-hook-v1\|guardrails from agent-config' "$1" || return 0
  if (( ! CHECK )); then
    t="$(mktemp)" || return 0
    sed -e 's/: agent-config-hook-v1:/: onbelay-hook-v1:/g' \
        -e 's/guardrails from agent-config/guardrails from onbelay/' "$1" > "$t" \
      && cat "$t" > "$1"
    rm -f "$t"
  fi
  echo "retagged the guard hooks in $(basename "$1")"
}

move "$C/.agent-config-origins" "$C/.onbelay-origins" append
move "$C/settings.json.before-agent-config" "$C/settings.json.before-onbelay" discard
move "$C/settings.json.agent-config-deny.json" "$C/settings.json.onbelay-deny.json" discard
retag "$C/settings.json"
retag "$X/hooks.json"

# The record of skills backed up during a 0.3.x conflict. Without it an
# uninstall cannot put them back.
L="$HOME/.local/share/agent-config/conflicts.json"
N="$HOME/.local/share/onbelay/conflicts.json"
if [[ -f "$L" && ! -f "$N" ]]; then
  (( CHECK )) || { mkdir -p "$(dirname "$N")" && mv "$L" "$N"; }
  echo "moved the skill-conflict backup record"
fi
exit 0
