#!/usr/bin/env bash
# Remove the wiring this repo installed. Leaves the repo itself alone.
#
#   ./uninstall.sh [guard|workflow|operator|full]
#
# Removes only symlinks that point into this repo, and strips only this repo's
# entries from Claude settings.json and Codex hooks.json. Your own skills,
# settings, hooks, and CLAUDE.md are left untouched. Backups are not deleted.
set -euo pipefail

# Resolve through symlinks, exactly as install.sh does. Without this, running
# uninstall through `~/bin/agent-uninstall -> repo/uninstall.sh` made $REPO
# `~/bin`, so every `readlink == "$REPO"*` test failed: it stripped the
# settings.json hooks (which do not use $REPO) and left every symlink in place,
# while reporting success.
_SRC="${BASH_SOURCE[0]}"
while [[ -L "$_SRC" ]]; do
  _DIR="$(cd "$(dirname "$_SRC")" && pwd)"
  _SRC="$(readlink "$_SRC")"
  [[ "$_SRC" != /* ]] && _SRC="$_DIR/$_SRC"
done
REPO="$(cd "$(dirname "$_SRC")" && pwd)"
CLAUDE_ROOT="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
CODEX_ROOT="${CODEX_HOME:-$HOME/.codex}"
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
skip() { printf '  \033[2m-\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }

# This script had NO argument parsing, so it ignored everything handed to it
# and `./uninstall.sh --dry-run` performed a real uninstall. install.sh carries
# the same guard, with the same comment, and the fix was never mirrored here.
#
# `--apply` is accepted and does nothing. Anything else is refused, because the
# flag someone reaches for when they want a preview must not perform the work.
PROFILE="full"
_profile_seen=0
_apply_seen=0
_bad_arg() {
  printf '\n  \033[31mABORTED:\033[0m %s\n' "$1" >&2
  printf '  There is no preview mode: this script always uninstalls.\n' >&2
  printf '  Usage: ./uninstall.sh [guard|workflow|operator|full]   (removes; --apply is accepted and ignored)\n\n' >&2
  exit 1
}
for _arg in "$@"; do
  case "$_arg" in
    guard|workflow|operator|full)
      (( _profile_seen )) && _bad_arg "more than one profile was supplied."
      PROFILE="$_arg"; _profile_seen=1
      ;;
    --apply)
      (( _apply_seen )) && _bad_arg "--apply was supplied more than once."
      _apply_seen=1
      ;;
    *) _bad_arg "unknown argument: $_arg" ;;
  esac
done
if [[ $# -gt 2 ]]; then _bad_arg "too many arguments."; fi
REMOVE_GUARD=0
REMOVE_WORKFLOW=0
REMOVE_OPERATOR=0
[[ "$PROFILE" == guard || "$PROFILE" == full ]] && REMOVE_GUARD=1
[[ "$PROFILE" == workflow || "$PROFILE" == full ]] && REMOVE_WORKFLOW=1
[[ "$PROFILE" == operator || "$PROFILE" == full ]] && REMOVE_OPERATOR=1

# Every path this repo has ever been installed from. Without it, moving or
# re-cloning the repo makes both scripts read our own previous symlinks as
# someone else's: install refuses 21 paths it actually owns, and uninstall walks
# away from 21 links it made, reporting success either way.
ORIGINS="$CLAUDE_ROOT/.onbelay-origins"
_is_our_target() {
  # PATH BOUNDARY, not a bare prefix. `$t == "$REPO"*` also matched any path
  # that merely shares a string prefix with the clone, so a user's own
  # `.../repo-dots/CLAUDE.md` next to `.../repo` was treated as ours: install
  # recorded no backup and uninstall deleted it. Deleting a symlink it did not
  # create is the one thing an uninstaller must never do.
  local t="${1%/}" o
  # The shapes install.sh actually creates, not "anything under the clone". A
  # repo cloned at a dotfiles root also contains the user's own stow tree, and
  # claiming all of it meant uninstall deleted their links with no backup
  # recorded. Current releases install skills, guard hooks, AGENTS.md, and the
  # project initializer. Old output-style and how-to shapes remain for cleanup.
  #
  # KEEP IN SYNC with the identical function in install.sh. Adding
  # output-styles to install.sh alone left the link behind on uninstall, and
  # the installer suite caught it within one run. If you add a shape, add it in
  # both files and add an install_test section for it.
  _ours_under() {
    [[ "$t" == "$1"/skills/* || "$t" == "$1"/operator-skills/* \
       || "$t" == "$1"/hooks/* || "$t" == "$1"/AGENTS.md \
       || "$t" == "$1"/templates/AGENTS.global.md \
       || "$t" == "$1"/scripts/agent-init \
       || "$t" == "$1"/output-styles/* || "$t" == "$1"/how-to-use.html ]]
  }
  _ours_under "$REPO" && return 0
  [[ -f "$ORIGINS" ]] || return 1
  # `|| [[ -n "$o" ]]` so a final line with no trailing newline is still read.
  # Without it an ORIGINS file written by an editor that strips the newline
  # left uninstall recognising nothing and reporting success.
  while IFS= read -r o || [[ -n "$o" ]]; do
    o="${o%/}"
    [[ -n "$o" ]] && _ours_under "$o" && return 0
  done < "$ORIGINS"
  return 1
}

_selected_target() {
  local t="${1%/}"
  (( REMOVE_GUARD )) && [[ "$t" == */hooks/* ]] && return 0
  if (( REMOVE_OPERATOR )); then
    [[ "$t" == */operator-skills/* || "$t" == */output-styles/* \
       || "$t" == */skills/wizard || "$t" == */skills/research \
       || "$t" == */skills/handoff ]] && return 0
  fi
  if (( REMOVE_WORKFLOW )); then
    [[ "$t" == */AGENTS.md || "$t" == */templates/AGENTS.global.md \
       || "$t" == */how-to-use.html \
       || "$t" == */scripts/agent-init ]] && return 0
    if [[ "$t" == */skills/* && "$t" != */skills/wizard \
          && "$t" != */skills/research && "$t" != */skills/handoff ]]; then
      return 0
    fi
  fi
  return 1
}

unlink_if_selected() {  # remove only a selected symlink owned by this repo
  local p="$1"
  if [[ -L "$p" ]] && _is_our_target "$(readlink "$p")" \
     && _selected_target "$(readlink "$p")"; then
    rm "$p"
    ok "removed $p"
  else
    skip "$p not ours, left alone"
  fi
}

# Every directory current or older releases may have filled with links, in one
# place. Retired output-style links remain so uninstall is complete on upgrade.
LINK_DIRS=()
(( REMOVE_WORKFLOW || REMOVE_OPERATOR )) \
  && LINK_DIRS+=("$CLAUDE_ROOT/skills" "$CODEX_ROOT/skills")
(( REMOVE_GUARD )) && LINK_DIRS+=("$CLAUDE_ROOT/hooks")
(( REMOVE_OPERATOR )) && LINK_DIRS+=("$CLAUDE_ROOT/output-styles")

echo "Removing onbelay $PROFILE wiring ($REPO)"
echo
echo "Symlinks"
if (( REMOVE_WORKFLOW )); then
  for p in "$CLAUDE_ROOT/CLAUDE.md" "$CODEX_ROOT/AGENTS.md" \
           "$HOME/AGENTS.md" "$CLAUDE_ROOT/how-to-use.html" \
           "$HOME/.local/bin/agent-init"; do
    [[ -e "$p" || -L "$p" ]] || continue
    unlink_if_selected "$p"
  done
  for p in "$CLAUDE_ROOT/CLAUDE.md" "$CODEX_ROOT/AGENTS.md"; do
    if [[ -e "$p" || -L "$p" ]]; then
      python3 "$REPO/scripts/manage_instructions.py" strip "$p" \
        && ok "removed On Belay routing from $p" \
        || warn "could not remove On Belay routing from $p"
    fi
  done
fi

for dir in "${LINK_DIRS[@]}"; do
  [[ -d "$dir" ]] || continue
  n=0
  for l in "$dir"/*; do
    if [[ -L "$l" ]] && _is_our_target "$(readlink "$l")" \
       && _selected_target "$(readlink "$l")"; then
      rm "$l"; n=$((n+1))
    fi
  done
  ok "removed $n links from $dir"
done

echo
echo "Hooks"
SETTINGS="$CLAUDE_ROOT/settings.json"
if (( REMOVE_GUARD )) && [[ -f "$SETTINGS" ]]; then
  if ! grep -qE 'onbelay-hook-v1|python3?[^\"]*[./]claude/hooks/(guard-(bash|files)|check-docs|welcome)\.py' "$SETTINGS" 2>/dev/null; then
    skip "settings.json has none of our hooks, left untouched"
  elif python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$SETTINGS" 2>/dev/null; then
    cp "$SETTINGS" "$SETTINGS.bak-uninstall-$(date +%Y%m%d-%H%M%S)"
    # Removes exactly what install added, and nothing the user wrote.
    # Shares its DENY list with the installer by being the same module,
    # which is what retires the drift assertion in tests/audit.py.
    python3 "$REPO/scripts/install_settings.py" strip "$SETTINGS"
    ok "guard hooks stripped from settings.json (backup kept)"
  else
    skip "settings.json is not valid JSON, left alone"
  fi
fi

CODEX_HOOKS="$CODEX_ROOT/hooks.json"
if (( REMOVE_GUARD )) && [[ -f "$CODEX_HOOKS" ]] \
   && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$CODEX_HOOKS" 2>/dev/null; then
  python3 "$REPO/scripts/install_codex_hooks.py" strip "$CODEX_HOOKS"
  ok "onbelay hooks stripped from Codex hooks.json"
else
  skip "codex hooks.json missing or invalid, left alone"
fi

# Directories install created and has now emptied. rmdir, never rm -r: if
# anything of the user's is left the removal must fail, not succeed quietly.
for d in "${LINK_DIRS[@]}"; do
  # `[[ ... ]] && rmdir` would abort the script under set -e: a non-empty
  # directory is the normal case, and the compound's status would be 1.
  if [[ -d "$d" && ! -L "$d" ]]; then
    rmdir "$d" 2>/dev/null || true
  fi
done

managed_state_remains() {
  local p dir l
  for p in "$CLAUDE_ROOT/CLAUDE.md" "$CODEX_ROOT/AGENTS.md" \
           "$HOME/AGENTS.md" "$CLAUDE_ROOT/how-to-use.html" \
           "$HOME/.local/bin/agent-init"; do
    [[ -L "$p" ]] && _is_our_target "$(readlink "$p")" && return 0
  done
  for dir in "$CLAUDE_ROOT/skills" "$CODEX_ROOT/skills" \
             "$CLAUDE_ROOT/hooks" "$CLAUDE_ROOT/output-styles"; do
    [[ -d "$dir" ]] || continue
    for l in "$dir"/*; do
      [[ -L "$l" ]] && _is_our_target "$(readlink "$l")" && return 0
    done
  done
  grep -qE 'python3?[^\"]*[./]claude/hooks/(guard-(bash|files)|check-docs|welcome)\.py' \
    "$SETTINGS" 2>/dev/null && return 0
  grep -qF 'guard-codex.py' "$CODEX_HOOKS" 2>/dev/null && return 0
  return 1
}

if ! managed_state_remains; then
  rm -f "$ORIGINS"
fi

CONFLICT_STATE="$HOME/.local/share/onbelay/conflicts.json"
if [[ -f "$CONFLICT_STATE" ]]; then
  python3 "$REPO/scripts/manage_conflicts.py" restore "$CONFLICT_STATE" \
    && ok "restored skills backed up during install" \
    || warn "some backed-up skill conflicts could not be restored"
fi

echo
echo "Done. Start a new agent session. The repo at $REPO is untouched."
echo "Existing configuration was preserved. Replaced skill conflicts were restored."
echo "Recovery copies remain until you choose to remove them."
