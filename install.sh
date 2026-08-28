#!/usr/bin/env bash
# Wire this repo into Claude Code and Codex.
#
#   ./install.sh standard          guardrails, workflow, and routing
#   ./install.sh guard             safety hooks only, and the bare default
#   ./install.sh workflow          skills, orchestration, and project init
#   ./install.sh operator          optional human-in-the-loop utilities
#   ./install.sh full              all three products
#   ./install.sh workflow --skills-only  omit global orchestration instructions
#   ./install.sh workflow --baseline  require global orchestration or refuse
#   ./install.sh <profile> --check report state, change nothing
#
# Idempotent. Existing shared configuration is merged, same-name skills are
# kept or backed up by one conflict decision, and unsupported path shapes are
# refused before wiring starts. It never edits a file it cannot parse.
#
# The two files it writes into rather than claims are shared configuration:
# ~/.claude/settings.json and ~/.codex/hooks.json. Existing keys and hooks are
# preserved, and one recovery copy of each pre-existing file is kept.
#
# To remove: ./uninstall.sh
set -euo pipefail

# Resolve through symlinks. `dirname "${BASH_SOURCE[0]}"` alone means running
# this via `~/bin/agent-install -> .../install.sh` aborts with "is this a
# complete clone?", which sends you hunting for the wrong problem.
# Plain `cd`, not `cd -P`: uninstall.sh resolves $REPO the same logical way and
# compares link targets against it as a string, and on macOS -P would turn
# /var into /private/var and stop every one of those comparisons matching.
_SRC="${BASH_SOURCE[0]}"
while [[ -L "$_SRC" ]]; do
  _DIR="$(cd "$(dirname "$_SRC")" && pwd)"
  _SRC="$(readlink "$_SRC")"
  [[ "$_SRC" != /* ]] && _SRC="$_DIR/$_SRC"
done
REPO="$(cd "$(dirname "$_SRC")" && pwd)"
CHECK=0
PROBLEMS=0
PROFILE="guard"
BASELINE_MODE="auto"
CONFLICT_MODE="auto"
_baseline_seen=0
_skills_only_seen=0
_profile_seen=0
_extras_seen=0
_bad_arg() {
  printf '\n  \033[31mABORTED:\033[0m %s\n' "$1" >&2
  printf '  Usage: ./install.sh [standard|guard(default)|workflow|operator|full] [--check] [--extras] [--keep-existing|--replace-conflicts]\n\n' >&2
  exit 1
}
# `--dry-run` used to perform a real install, so unknown flags remain fatal.
for _arg in "$@"; do
  case "$_arg" in
    standard|guard|workflow|operator|full)
      (( _extras_seen )) && _bad_arg "--extras cannot be combined with a profile."
      (( _profile_seen )) && _bad_arg "more than one profile was supplied."
      PROFILE="$_arg"; _profile_seen=1
      ;;
    --extras)
      (( _profile_seen )) && _bad_arg "--extras cannot be combined with a profile."
      (( _extras_seen )) && _bad_arg "--extras was supplied more than once."
      _extras_seen=1
      PROFILE="full"
      ;;
    --check)
      (( CHECK )) && _bad_arg "--check was supplied more than once."
      CHECK=1
      ;;
    --baseline)
      (( _baseline_seen )) && _bad_arg "--baseline was supplied more than once."
      (( _skills_only_seen )) && _bad_arg "--baseline and --skills-only cannot be combined."
      _baseline_seen=1
      BASELINE_MODE="required"
      ;;
    --skills-only)
      (( _skills_only_seen )) && _bad_arg "--skills-only was supplied more than once."
      (( _baseline_seen )) && _bad_arg "--baseline and --skills-only cannot be combined."
      _skills_only_seen=1
      BASELINE_MODE="off"
      ;;
    --keep-existing)
      [[ "$CONFLICT_MODE" == auto ]] || _bad_arg "more than one conflict option was supplied."
      CONFLICT_MODE="keep"
      ;;
    --replace-conflicts)
      [[ "$CONFLICT_MODE" == auto ]] || _bad_arg "more than one conflict option was supplied."
      CONFLICT_MODE="replace"
      ;;
    *) _bad_arg "unknown argument: $_arg" ;;
  esac
done
if [[ $# -gt 4 ]]; then _bad_arg "too many arguments."; fi
INSTALL_GUARD=0
INSTALL_WORKFLOW=0
INSTALL_OPERATOR=0
[[ "$PROFILE" == standard || "$PROFILE" == guard || "$PROFILE" == full ]] && INSTALL_GUARD=1
[[ "$PROFILE" == standard || "$PROFILE" == workflow || "$PROFILE" == full ]] && INSTALL_WORKFLOW=1
[[ "$PROFILE" == operator || "$PROFILE" == full ]] && INSTALL_OPERATOR=1
(( (_baseline_seen || _skills_only_seen) && ! INSTALL_WORKFLOW )) \
  && _bad_arg "--baseline and --skills-only require the workflow or full profile."
INSTALL_BASELINE=0
REMOVE_AUTO_BASELINE=0
WORKFLOW_SKILLS=(navigate prototype bootstrap setup to-spec breakdown domain-modeling architect tdd diagnose review unstick ship)
OPERATOR_SKILLS=(research wizard handoff)

CLAUDE_ROOT="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
CODEX_ROOT="${CODEX_HOME:-$HOME/.codex}"

# An extras skill already linked here means a PREVIOUS install was asked for
# the extras. Deriving INSTALL_OPERATOR from the profile alone made an upgrade
# ignore them, which left those eight links bound to the previous install root:
# not migrated, and not removed either. Nothing reported it while that root
# still existed, because the links still resolved; the first signal was doctor
# failing after the root was deleted, by which point the skills were already
# gone. Adopting what is installed is what makes the README's "re-running the
# command repairs or upgrades the installation" true for everything it owns.
#
# Gated on INSTALL_WORKFLOW so `install guard` stays exactly what it says: a
# guard-only profile does not start pulling in skills because some are present.
if (( INSTALL_WORKFLOW && ! INSTALL_OPERATOR )); then
  for _s in "${OPERATOR_SKILLS[@]}"; do
    [[ -L "$CLAUDE_ROOT/skills/$_s" ]] && { INSTALL_OPERATOR=1; break; }
  done
fi

SKILL_ROOTS=()
(( INSTALL_WORKFLOW )) && SKILL_ROOTS+=("$REPO/skills")
(( INSTALL_OPERATOR )) && SKILL_ROOTS+=("$REPO/operator-skills")

COMPACT="${ONBELAY_COMPACT:-0}"

ok()   { (( COMPACT )) || printf '  \033[32m✓\033[0m %s\n' "$1"; }
status() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
detail_warn() { (( COMPACT )) || warn "$1"; }
section() { (( COMPACT )) || { echo; echo "$1"; }; }
err()  { printf '  \033[31m✗\033[0m %s\n' "$1"; PROBLEMS=$((PROBLEMS+1)); }
die()  {
  if (( CHECK )); then printf '  \033[31m✗\033[0m %s\n' "$1"; PROBLEMS=$((PROBLEMS+1)); return 0; fi
  printf '\n  \033[31mABORTED:\033[0m %s\n\n' "$1" >&2; exit 1
}

# Every path this repo has ever been installed from. Without it, moving or
# re-cloning the repo makes the NEXT install read our own previous symlinks as
# a dotfile manager's and record 21 `.baklink-` files pointing at the old path;
# uninstall then dutifully restores all 21 as dangling links, which is worse
# than doing nothing, and reports success.
ORIGINS="$CLAUDE_ROOT/.onbelay-origins"

# A 0.3.x machine read as covered in files we did not write: no origins file
# under the current name meant `_is_our_target` denied all 33 of our own links,
# and install aborted asking the user to `mv` our own work. This has to run
# before the first `_is_our_target` call, which is the baseline check below.
# `|| true` because `set -e` turns an absent script into a bare exit 127 with
# nothing printed. Only 0.3.x machines need this, so degrading to "no migration"
# is survivable for everyone else; shipping it is enforced by the npx suite.
MIGRATED="$(bash "$REPO/scripts/migrate-legacy.sh" "$CLAUDE_ROOT" "$CODEX_ROOT" \
  "$CHECK" 2>/dev/null || true)"

_is_our_target() {
  # PATH BOUNDARY, not a bare prefix. `$t == "$REPO"*` also matched any path
  # that merely shares a string prefix with the clone, so a user's own
  # `.../repo-dots/CLAUDE.md` next to `.../repo` was treated as ours: install
  # recorded no backup and uninstall deleted it. Deleting a symlink it did not
  # create is the one thing an uninstaller must never do.
  local t="${1%/}" o
  # Only shapes current or older releases create, not "anything under the
  # clone". A repo cloned at a dotfiles root also contains the user's own stow
  # tree, and claiming all of it meant uninstall deleted their links with no
  # backup recorded. Current releases install skills, guard hooks, and
  # AGENTS.md and the project initializer. Output-style and how-to shapes remain
  # only so upgrades recognize links created by older releases. A new link shape must be added here and to
  # uninstall.sh or the uninstaller will not own it.
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

# A clean workflow install gets one shared orchestration source. Existing user
# instructions receive the same bounded, removable routing block.
_baseline_available() {
  local p
  for p in "$CLAUDE_ROOT/CLAUDE.md" "$CODEX_ROOT/AGENTS.md"; do
    [[ -e "$p" || -L "$p" ]] || continue
    if [[ -L "$p" ]] && _is_our_target "$(readlink "$p")"; then
      continue
    fi
    return 1
  done
  return 0
}
_baseline_has_owned_link() {
  local p
  for p in "$CLAUDE_ROOT/CLAUDE.md" "$CODEX_ROOT/AGENTS.md"; do
    [[ -L "$p" ]] && _is_our_target "$(readlink "$p")" && return 0
  done
  return 1
}
if (( INSTALL_WORKFLOW )); then
  case "$BASELINE_MODE" in
    off)
      INSTALL_BASELINE=0
      _baseline_has_owned_link && REMOVE_AUTO_BASELINE=1
      ;;
    auto|required) INSTALL_BASELINE=1 ;;
  esac
fi

# Paths we want that are occupied by something the user owns. Collected by the
# preflight and printed together: finding out about them one `mv` at a time,
# across three runs, is its own kind of hostile.
OCCUPIED=()
SKILL_CONFLICTS=()

claim() {  # claim <path> -- free, or already ours, or record it
  local p="$1"
  [[ -e "$p" || -L "$p" ]] || return 0            # free
  if [[ -L "$p" ]]; then
    # Ours, from this clone or a previous location.
    _is_our_target "$(readlink "$p")" && return 0
    # Dangling: the target is gone, so the link points at nothing and there is
    # nothing to lose by replacing it. Refusing here would mean a moved or
    # deleted clone leaves a machine that re-running install can never repair.
    [[ -e "$p" ]] || { warn "replacing a broken link at $p (its target is gone)"; return 0; }
  fi
  OCCUPIED+=("$p")
  return 1
}

claim_shared_file() {  # claim_shared_file <path> -- every symlink is occupied
  local p="$1"
  [[ -L "$p" ]] || return 0
  OCCUPIED+=("$p")
  return 1
}

claim_skill() {  # exact skill names coexist unless the user chooses replacement
  local p="$1"
  [[ -e "$p" || -L "$p" ]] || return 0
  if [[ -L "$p" ]]; then
    _is_our_target "$(readlink "$p")" && return 0
  fi
  SKILL_CONFLICTS+=("$p")
}

# Everything install writes, checked BEFORE anything is written. The list has
# to be exhaustive: a path that installs without being claimed here is a path
# that can still clobber something.
preflight_paths() {
  local d name f root
  # Existing instruction files are merged through a bounded managed block.
  # Clean paths become symlinks to one shared source.
  if (( INSTALL_GUARD )); then
    # Shared JSON files are merged. The helpers preserve a dotfile symlink by
    # updating its target instead of replacing the link.
    :
  fi
  # A container directory is only a conflict when it is a SYMLINK: a real
  # directory is where we put our links, alongside whatever else is in it.
  if (( INSTALL_WORKFLOW || INSTALL_OPERATOR )); then
    for d in "$CLAUDE_ROOT/skills" "$CODEX_ROOT/skills"; do
      [[ -L "$d" && ! -d "$d" ]] && { claim "$d" || true; }
    done
    for root in "${SKILL_ROOTS[@]}"; do
      for d in "$root"/*/; do
        [[ -f "$d/SKILL.md" ]] || continue
        name="$(basename "$d")"
        claim_skill "$CLAUDE_ROOT/skills/$name"
        claim_skill "$CODEX_ROOT/skills/$name"
      done
    done
  fi
  if (( INSTALL_WORKFLOW )); then
    [[ -L "$HOME/.local" && ! -d "$HOME/.local" ]] && { claim "$HOME/.local" || true; }
    [[ -L "$HOME/.local/bin" && ! -d "$HOME/.local/bin" ]] && { claim "$HOME/.local/bin" || true; }
    claim "$HOME/.local/bin/agent-init" || true
  fi
  if (( INSTALL_OPERATOR )); then
    [[ -L "$CLAUDE_ROOT/output-styles" && ! -d "$CLAUDE_ROOT/output-styles" ]] && { claim "$CLAUDE_ROOT/output-styles" || true; }
    for f in "$REPO"/output-styles/*.md; do
      [[ -f "$f" ]] && { claim "$CLAUDE_ROOT/output-styles/$(basename "$f")" || true; }
    done
  fi
  if (( INSTALL_GUARD )); then
    [[ -L "$CLAUDE_ROOT/hooks" && ! -d "$CLAUDE_ROOT/hooks" ]] && { claim "$CLAUDE_ROOT/hooks" || true; }
    for f in "$REPO"/hooks/guard*.py; do
      [[ -f "$f" ]] && { claim "$CLAUDE_ROOT/hooks/$(basename "$f")" || true; }
    done
  fi
}

refuse_if_occupied() {
  (( ${#OCCUPIED[@]} )) || return 0
  printf '\n  \033[31mABORTED:\033[0m %d path(s) are occupied by something that is not ours.\n\n' \
    "${#OCCUPIED[@]}" >&2
  printf '  Nothing has been changed. This installer will not move, copy or delete\n' >&2
  printf '  a file it did not create, because an installer that can do that quietly\n' >&2
  printf '  is how people lose configuration they cannot get back.\n\n' >&2
  local p
  for p in "${OCCUPIED[@]}"; do
    printf '    mv ' >&2
    printf '%q ' "$p" >&2
    printf '%q\n' "$p.mine" >&2
  done
  printf '\n  Run those, then ./install.sh again.\n' >&2
  printf '  (Using stow or chezmoi? Unstow these paths first.)\n\n' >&2
  exit 1
}

CONFLICT_STATE="$HOME/.local/share/onbelay/conflicts.json"
resolve_skill_conflicts() {
  (( ${#SKILL_CONFLICTS[@]} )) || return 0
  if (( CHECK )); then
    warn "${#SKILL_CONFLICTS[@]} existing skill path(s) are kept and still available"
    return 0
  fi
  if [[ "$CONFLICT_MODE" == auto ]]; then
    if [[ "${ONBELAY_NONINTERACTIVE:-}" == 1 || ! -t 0 ]]; then
      CONFLICT_MODE="keep"
    else
      printf '\n%d installed skill name(s) already exist.\n' "${#SKILL_CONFLICTS[@]}"
      printf 'Keep them [K], back them up and use On Belay [R], or cancel [C]? '
      IFS= read -r answer
      case "${answer:-K}" in
        r|R) CONFLICT_MODE="replace" ;;
        c|C) printf 'Cancelled. Nothing changed.\n'; exit 1 ;;
        *) CONFLICT_MODE="keep" ;;
      esac
    fi
  fi
  if [[ "$CONFLICT_MODE" == replace ]]; then
    python3 "$REPO/scripts/manage_conflicts.py" backup "$CONFLICT_STATE" \
      "${SKILL_CONFLICTS[@]}" || die "could not back up conflicting skills"
    ok "backed up ${#SKILL_CONFLICTS[@]} conflicting skill path(s) for uninstall"
  else
    warn "kept ${#SKILL_CONFLICTS[@]} existing skill path(s); installed everything else"
  fi
}

kept_skill_conflict() {
  local candidate="$1" conflict
  [[ "$CONFLICT_MODE" == keep ]] || return 1
  for conflict in "${SKILL_CONFLICTS[@]}"; do
    [[ "$conflict" == "$candidate" ]] && return 0
  done
  return 1
}

# Prune links to skills this repo no longer ships. Both loops above iterate
# what EXISTS in the repo, so a renamed or deleted skill leaves a dangling
# symlink that both agents still scan, and --check called it "all good".
# It is also what sets up the silent-abort case: a dangling entry whose name
# later comes back is what used to crash the installer.
prune_stale() {  # prune_stale <dir> <display-kind> <source-root>...
  local dir="$1" kind="$2" l source_root matches
  shift 2
  [[ -d "$dir" && ! -L "$dir" ]] || return 0
  for l in "$dir"/*; do
    [[ -L "$l" ]] || continue
    _t="$(readlink "$l")"
    # _is_our_target, not a raw $REPO prefix: a link left by a PREVIOUS
    # location is exactly the stale one worth pruning, and matching only the
    # current path missed it.
    matches=0
    for source_root in "$@"; do
      [[ "$_t" == */"$source_root"/* ]] && { matches=1; break; }
    done
    (( matches )) || continue
    _is_our_target "$_t" || continue
    [[ -e "$l" ]] && continue
    if (( CHECK )); then
      err "stale ${kind%s} link $(basename "$l"): this repo no longer ships it"
    else
      rm -f "$l"; warn "removed stale ${kind%s} link $(basename "$l")"
    fi
  done
}

prune_selected_skills() {  # prune_selected_skills <host skill dir>
  local dir="$1"
  (( INSTALL_WORKFLOW )) && prune_stale "$dir" skills skills
  (( INSTALL_OPERATOR )) && prune_stale "$dir" skills operator-skills
  return 0
}

link() {  # link <target> <linkname>
  # The preflight has already refused anything here that is not ours, so the
  # only thing this can replace is one of our own links from an earlier run.
  local target="$1" name="$2"
  if [[ -L "$name" ]]; then
    if [[ "$(readlink "$name")" == "$target" ]]; then ok "$name"; return; fi
    (( CHECK )) && { err "$name points at $(readlink "$name")"; return; }
    rm "$name"
  elif [[ -e "$name" ]]; then
    # Unreachable after preflight. Refuse rather than assume: a path that got
    # here is a hole in preflight_paths, and deleting it would be the exact
    # behaviour this design removed.
    (( CHECK )) && { err "$name exists and is not a symlink"; return; }
    printf '\n  \033[31mABORTED:\033[0m %s exists and preflight did not claim it.\n' "$name" >&2
    printf '  That is a bug in preflight_paths. Nothing was changed.\n\n' >&2
    exit 1
  else
    (( CHECK )) && { err "$name missing"; return; }
  fi
  ln -s "$target" "$name"
  ok "$name -> $target"
}

route_instructions() {  # route_instructions <host instruction path>
  local path="$1" source="$REPO/templates/AGENTS.global.md"
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    link "$source" "$path"
    return
  fi
  if [[ -L "$path" ]] && _is_our_target "$(readlink "$path")"; then
    link "$source" "$path"
    return
  fi
  if (( CHECK )); then
    python3 "$REPO/scripts/manage_instructions.py" check "$path" "$source" \
      && ok "$path routing block" || err "$path routing block missing or stale"
  else
    # One recovery copy before the first edit, the same rule settings.json
    # gets. Instruction files had none, and the merge replaces whatever sits
    # between the markers: a user who had already used those exact markers
    # lost the text inside them with nothing to restore from.
    if [[ ! -e "$path.before-onbelay" ]]; then
      cp "$path" "$path.before-onbelay"
    fi
    python3 "$REPO/scripts/manage_instructions.py" merge "$path" "$source" \
      || die "could not merge routing instructions into $path"
    ok "$path preserved with On Belay routing"
  fi
}

# ---------------------------------------------------------------- preflight
# Everything that could fail is checked BEFORE anything is written. A
# half-install is worse than no install: it can leave CLAUDE.md promising
# guardrails that were never wired.
if (( ! COMPACT )); then
  echo "onbelay $PROFILE profile at $REPO"
  (( CHECK )) && echo "(check only, nothing will change)"
  echo
  echo "Preflight"
fi

if [[ -n "$MIGRATED" ]]; then
  if (( CHECK )); then
    # Say this BEFORE the per-path errors. Unexplained, they read as damage;
    # they are one cause with one fix, and the reader deserves to know that
    # before scrolling past a dozen of them.
    warn "this machine still carries a 0.3.x (agent-config) install."
    warn "the problems below are that rename, not damage. Installing migrates it."
  else
    while IFS= read -r _change; do
      [[ -n "$_change" ]] && ok "migrated from agent-config: $_change"
    done <<<"$MIGRATED"
  fi
fi

GUARD_READY=1
if (( INSTALL_GUARD )); then
  if command -v python3 >/dev/null 2>&1; then
    PYV="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)'; then
      ok "python3 $PYV"
    else
      die "python3 is $PYV; 3.9 or newer is required."
      GUARD_READY=0
    fi
  else
    die "python3 not found on PATH. The guard hooks are Python; install it first."
    GUARD_READY=0
  fi

  if ! command -v git >/dev/null 2>&1; then
    die "git not found on PATH. The guard rules shell out to git, and without it a branch lookup fails, which the guard treats as protected. Install git first."
    GUARD_READY=0
  fi
fi

# Anything we WRITE must be a regular file, and anything we fill with symlinks
# must be a directory. Each of these otherwise aborts partway with a bare
# `mkdir:`/`IsADirectoryError`, leaving a half-install, or worse: a hooks.json
# that is a directory makes `mv` move the temp file INTO it and report success
# while Codex ends up with no guardrails at all.
if (( INSTALL_GUARD )); then
  for f in "$CLAUDE_ROOT/settings.json" "$CODEX_ROOT/hooks.json"; do
    if [[ -e "$f" && ! -f "$f" ]]; then
      die "$f exists but is not a regular file. Move it aside first."
    fi
  done
  if [[ -e "$CLAUDE_ROOT/hooks" && ! -d "$CLAUDE_ROOT/hooks" ]]; then
    die "$CLAUDE_ROOT/hooks exists but is not a directory. Move it aside first."
  fi
  for f in hooks/guard_rules.py hooks/guard_parse.py hooks/guard_git.py \
           hooks/guard_repo.py hooks/guard_paths.py \
           hooks/guard_secrets.py hooks/guard_db.py hooks/guard_tools.py \
           hooks/guard-bash.py hooks/guard-files.py hooks/guard-codex.py \
           scripts/install_settings.py scripts/install_codex_hooks.py; do
    [[ -f "$REPO/$f" ]] || die "missing $f. Is this a complete clone?"
  done
  ok "guard scripts present"
fi
if (( INSTALL_WORKFLOW || INSTALL_OPERATOR )); then
  if [[ -e "$CODEX_ROOT" && ! -d "$CODEX_ROOT" ]]; then
    die "$CODEX_ROOT exists but is not a directory. Move it aside first."
  fi
  for d in "$CLAUDE_ROOT/skills" "$CODEX_ROOT/skills"; do
    if [[ -e "$d" && ! -d "$d" ]]; then
      die "$d exists but is not a directory. Move it aside first."
    fi
  done
fi
if (( INSTALL_WORKFLOW )); then
  if [[ -e "$HOME/.local" && ! -d "$HOME/.local" ]]; then
    die "$HOME/.local exists but is not a directory. Move it aside first."
  fi
  if [[ -d "$HOME/.local" && ! -e "$HOME/.local/bin" && ! -w "$HOME/.local" ]]; then
    die "$HOME/.local is not writable. Nothing has been changed."
  fi
  if [[ -e "$HOME/.local/bin" && ! -d "$HOME/.local/bin" ]]; then
    die "$HOME/.local/bin exists but is not a directory. Move it aside first."
  fi
  for f in scripts/agent-init templates/AGENTS.project.md; do
    [[ -f "$REPO/$f" ]] || die "missing $f. Is this a complete clone?"
  done
  ok "project instruction initializer present"
fi
if (( INSTALL_OPERATOR )) && [[ -e "$CLAUDE_ROOT/output-styles" && ! -d "$CLAUDE_ROOT/output-styles" ]]; then
  die "$CLAUDE_ROOT/output-styles exists but is not a directory. Move it aside first."
fi
if (( INSTALL_OPERATOR )); then
  for f in output-styles/eli5.md output-styles/terse.md \
           operator-profiles/codex/eli5.AGENTS.md \
           operator-profiles/codex/terse.AGENTS.md; do
    [[ -f "$REPO/$f" ]] || die "missing $f. Is this a complete clone?"
  done
  ok "operator communication profiles present"
fi
if (( INSTALL_BASELINE )) && [[ ! -f "$REPO/templates/AGENTS.global.md" ]]; then
  die "missing templates/AGENTS.global.md. Is this a complete clone?"
fi
if (( INSTALL_BASELINE )); then
  for f in "$CLAUDE_ROOT/CLAUDE.md" "$CODEX_ROOT/AGENTS.md"; do
    if [[ -e "$f" || -L "$f" ]]; then
      if [[ -L "$f" ]] && _is_our_target "$(readlink "$f")"; then
        continue
      fi
      python3 "$REPO/scripts/manage_instructions.py" validate "$f" \
        || die "$f has malformed On Belay markers or is not a regular file. Fix it before installing."
    fi
  done
fi

require_writable_destination() {
  local requested="$1" kind="${2:-file}" destination="$1" ancestor parent
  if [[ -L "$destination" ]]; then
    destination="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$destination")"
  fi
  if [[ -e "$destination" ]]; then
    [[ -w "$destination" ]] \
      || die "$requested is not writable. Nothing has been changed."
    if [[ "$kind" == dir && ! -x "$destination" ]]; then
      die "$requested is not searchable. Nothing has been changed."
    fi
    if [[ "$kind" == file ]]; then
      parent="$(dirname "$destination")"
      [[ -w "$parent" && -x "$parent" ]] \
        || die "$requested cannot be updated atomically below $parent. Nothing has been changed."
    fi
    return
  fi
  ancestor="$(dirname "$destination")"
  while [[ ! -e "$ancestor" ]]; do
    [[ "$ancestor" == "$(dirname "$ancestor")" ]] && break
    ancestor="$(dirname "$ancestor")"
  done
  [[ -d "$ancestor" && -w "$ancestor" && -x "$ancestor" ]] \
    || die "$requested cannot be created below $ancestor. Nothing has been changed."
}

# Existing destination containers must be writable before the first link or
# ownership record is created. Checking only ~/.claude missed a read-only
# output-styles directory and left a partial operator installation behind.
DESTINATION_DIRS=()
if (( INSTALL_WORKFLOW || INSTALL_OPERATOR )); then
  DESTINATION_DIRS+=("$CLAUDE_ROOT/skills")
  [[ -d "$CODEX_ROOT" ]] && DESTINATION_DIRS+=("$CODEX_ROOT/skills")
fi
(( INSTALL_WORKFLOW )) && DESTINATION_DIRS+=("$HOME/.local/bin")
(( INSTALL_OPERATOR )) && DESTINATION_DIRS+=("$CLAUDE_ROOT/output-styles")
(( INSTALL_GUARD )) && DESTINATION_DIRS+=("$CLAUDE_ROOT/hooks")
for d in "${DESTINATION_DIRS[@]}"; do
  if [[ -d "$d" && ! -w "$d" ]]; then
    die "$d is not writable. Nothing has been changed."
  fi
done

# Missing custom roots and symlinked instruction files need the same preflight.
# Otherwise Claude can be fully wired before a later Codex mkdir or instruction
# merge discovers its destination is read-only.
if (( ! CHECK )); then
  require_writable_destination "$CLAUDE_ROOT" dir
  require_writable_destination "$ORIGINS"
  (( INSTALL_GUARD )) && {
    require_writable_destination "$CLAUDE_ROOT/settings.json"
    require_writable_destination "$CLAUDE_ROOT/hooks" dir
    require_writable_destination "$CODEX_ROOT" dir
    require_writable_destination "$CODEX_ROOT/hooks.json"
  }
  (( INSTALL_WORKFLOW || INSTALL_OPERATOR )) && {
    require_writable_destination "$CLAUDE_ROOT/skills" dir
    require_writable_destination "$CODEX_ROOT" dir
    require_writable_destination "$CODEX_ROOT/skills" dir
  }
  (( INSTALL_WORKFLOW )) && require_writable_destination "$HOME/.local/bin" dir
  (( INSTALL_OPERATOR )) && require_writable_destination "$CLAUDE_ROOT/output-styles" dir
  if (( INSTALL_BASELINE )); then
    require_writable_destination "$CLAUDE_ROOT/CLAUDE.md"
    require_writable_destination "$CODEX_ROOT/AGENTS.md"
  fi
fi

# Codex hooks.json is shared configuration, just like Claude settings.json.
# Validate it before any mutation so a malformed user file cannot leave a
# half-install after the Claude half has already been wired.
if (( INSTALL_GUARD && GUARD_READY )) && [[ -f "$CODEX_ROOT/hooks.json" ]]; then
  python3 "$REPO/scripts/install_codex_hooks.py" validate "$CODEX_ROOT/hooks.json" \
    || die "$CODEX_ROOT/hooks.json is not valid hook configuration. Fix or move it first; this script will not rewrite a file whose shape it does not understand."
  ok "existing Codex hooks.json parses and has the expected shape"
fi

# Nothing has been written yet, and nothing will be if any path we want is
# occupied by something the user owns. --check reports instead: it is
# read-only by contract, so it must not abort on a state it is meant to
# describe.
if (( ! CHECK )); then
  preflight_paths
  refuse_if_occupied
fi

# Every skill is a real directory now; nothing here is a symlink into a vendor
# tree, so a ZIP download or a clone with core.symlinks=false can no longer
# silently produce a half-installed suite. Count them so a truncated checkout
# is still obvious.
# `|| true` is load-bearing: with `set -euo pipefail`, a glob that matches
# nothing makes ls exit non-zero, pipefail propagates it, and the script died
# SILENTLY before it could say what was wrong. An installer that aborts with no
# message is worse than one that aborts.
if (( INSTALL_WORKFLOW )); then
  for _skill in "${WORKFLOW_SKILLS[@]}"; do
    [[ -f "$REPO/skills/$_skill/SKILL.md" ]] \
      || die "missing workflow skill $_skill. Is this a complete clone?"
  done
  ok "${#WORKFLOW_SKILLS[@]} required workflow skills present"
fi
if (( INSTALL_OPERATOR )); then
  for _skill in "${OPERATOR_SKILLS[@]}"; do
    [[ -f "$REPO/operator-skills/$_skill/SKILL.md" ]] \
      || die "missing operator skill $_skill. Is this a complete clone?"
  done
  ok "${#OPERATOR_SKILLS[@]} required operator skills present"
fi

if (( ! CHECK )); then
  mkdir -p "$CLAUDE_ROOT" 2>/dev/null || die "cannot create $CLAUDE_ROOT (is HOME read-only?)"
  touch "$CLAUDE_ROOT/.onbelay-write-test" 2>/dev/null \
    || die "$CLAUDE_ROOT is not writable. Nothing has been changed."
  rm -f "$CLAUDE_ROOT/.onbelay-write-test"
  touch "$HOME/.onbelay-write-test" 2>/dev/null \
    || die "$HOME is not writable. Nothing has been changed."
  rm -f "$HOME/.onbelay-write-test"
  # ~/.codex too, or the Claude half completes and the Codex half aborts under
  # set -e, which is exactly the half-install the preflight promises to prevent.
  if [[ -d "$CODEX_ROOT" ]]; then
    touch "$CODEX_ROOT/.onbelay-write-test" 2>/dev/null \
      || die "$CODEX_ROOT is not writable. Nothing has been changed."
    rm -f "$CODEX_ROOT/.onbelay-write-test"
  fi
  ok "HOME is writable"
fi

if (( INSTALL_GUARD )) && [[ -L "$CLAUDE_ROOT/settings.json" && ! -e "$CLAUDE_ROOT/settings.json" ]]; then
  die "$CLAUDE_ROOT/settings.json is a symlink pointing at something that does not exist. Fix or remove it first; installing over it would leave the hooks unwired."
fi

# A dangling Codex hooks.json is REPAIRED, not refused: the merge writes the
# file through the link and case 18d pins that. It only fails when the target's
# PARENT is missing too, because then there is nothing to create the file in,
# and that failure used to land after the whole Claude half was already wired.
# So the test is the parent directory, not the link.
if (( INSTALL_GUARD )) && [[ -L "$CODEX_ROOT/hooks.json" && ! -e "$CODEX_ROOT/hooks.json" ]]; then
  _codex_target="$(readlink "$CODEX_ROOT/hooks.json")"
  [[ "$_codex_target" != /* ]] && _codex_target="$CODEX_ROOT/$_codex_target"
  [[ -d "$(dirname "$_codex_target")" ]] \
    || die "$CODEX_ROOT/hooks.json points into $(dirname "$_codex_target"), which does not exist. Create it or remove the link first; installing over it would wire Claude and leave Codex without guardrails."
fi

if (( INSTALL_GUARD && GUARD_READY )); then
  python3 "$REPO/scripts/install_settings.py" validate "$CLAUDE_ROOT/settings.json" 2>/dev/null \
    || die "$CLAUDE_ROOT/settings.json or its onbelay ownership state is invalid. Fix or move it first; this script will not rewrite state whose shape it does not understand."
  [[ -f "$CLAUDE_ROOT/settings.json" ]] \
    && ok "existing settings.json parses and has the expected shape"
fi

resolve_skill_conflicts

# Auto mode is all-or-nothing across hosts. If the user has replaced one
# instruction path since an earlier install, remove our remaining sibling link
# only after every preflight and correctness gate has passed. --check reports
# the split instead of calling it healthy.
if (( REMOVE_AUTO_BASELINE )); then
  if (( CHECK )); then
    if [[ "$BASELINE_MODE" == off ]]; then
      err "global onbelay instructions are still installed; run without --check to remove them for --skills-only mode"
    else
      err "global instructions are split: one host still uses onbelay while the other is user-owned"
    fi
  else
    for p in "$CLAUDE_ROOT/CLAUDE.md" "$CODEX_ROOT/AGENTS.md"; do
      if [[ -L "$p" ]] && _is_our_target "$(readlink "$p")"; then
        rm "$p"
        warn "removed onbelay baseline at $p so both hosts preserve user-owned instructions"
      fi
    done
  fi
fi

# Record where we are installing from, so a later run from a different path
# still recognises these links as ours. AFTER every gate: writing it during
# preflight meant an aborted install still widened _is_our_target permanently.
if (( ! CHECK )); then
  if ! { [[ -f "$ORIGINS" ]] && grep -qxF -- "$REPO" "$ORIGINS"; }; then
    # Terminate a previous line that lost its newline first, or the two paths
    # concatenate into one bogus origin and the older one is lost. Round 16
    # fixed the READ side of this and left the write.
    if [[ -s "$ORIGINS" && -n "$(tail -c 1 "$ORIGINS")" ]]; then
      printf '\n' >> "$ORIGINS" 2>/dev/null || true
    fi
    printf '%s\n' "$REPO" >> "$ORIGINS" 2>/dev/null || true
  fi
fi

if (( INSTALL_WORKFLOW )); then
  (( CHECK )) || mkdir -p "$HOME/.local/bin"
  link "$REPO/scripts/agent-init" "$HOME/.local/bin/agent-init"
  case ":${PATH:-}:" in
    *:"$HOME/.local/bin":*) ;;
    *) detail_warn "$HOME/.local/bin is not on PATH; run $HOME/.local/bin/agent-init directly or add that directory to PATH." ;;
  esac
fi

# ---------------------------------------------------------------- claude code
section "Claude Code"
if (( INSTALL_WORKFLOW || INSTALL_OPERATOR )); then
(( CHECK )) || mkdir -p "$CLAUDE_ROOT/skills"
# Link each skill individually rather than replacing ~/.claude/skills wholesale.
# Taking over the directory would silently stop any skill the user wrote
# themselves, which is not a trade an installer gets to make on their behalf.
n=0; missing=0
for root in "${SKILL_ROOTS[@]}"; do
  for d in "$root"/*/; do
    [[ -f "$d/SKILL.md" ]] || continue
    name="$(basename "$d")"
    if (( CHECK )); then
      if [[ -L "$CLAUDE_ROOT/skills/$name" && "$(readlink "$CLAUDE_ROOT/skills/$name")" == "$d" ]]; then
        :
      elif [[ -f "$CLAUDE_ROOT/skills/$name/SKILL.md" ]]; then
        warn "claude skill $name is provided by an existing installation"
      else
        err "claude skill $name missing"; missing=1
      fi
    else
      kept_skill_conflict "$CLAUDE_ROOT/skills/$name" && continue
      if [[ -L "$CLAUDE_ROOT/skills/$name" && "$(readlink "$CLAUDE_ROOT/skills/$name")" == "$d" ]]; then
        : # already ours; do NOT re-record it as if it were the user's
      elif [[ -L "$CLAUDE_ROOT/skills/$name" && ! -e "$CLAUDE_ROOT/skills/$name" ]]; then
        rm "$CLAUDE_ROOT/skills/$name"
      elif [[ -e "$CLAUDE_ROOT/skills/$name" || -L "$CLAUDE_ROOT/skills/$name" ]]; then
        if _is_our_target "$(readlink "$CLAUDE_ROOT/skills/$name" 2>/dev/null || true)"; then
          rm -f "$CLAUDE_ROOT/skills/$name"
        else
          continue
        fi
      fi
      ln -sfn "$d" "$CLAUDE_ROOT/skills/$name"; n=$((n+1))
    fi
  done
done
prune_selected_skills "$CLAUDE_ROOT/skills"
(( CHECK )) && (( ! missing )) && ok "all skills linked into ~/.claude/skills"
(( CHECK )) || ok "$n skills linked into ~/.claude/skills (your own are untouched)"

fi

if (( INSTALL_OPERATOR )); then
  (( CHECK )) || mkdir -p "$CLAUDE_ROOT/output-styles"
  sn=0; style_missing=0
  for f in "$REPO"/output-styles/*.md; do
    [[ -f "$f" ]] || continue
    name="$(basename "$f")"
    if (( CHECK )); then
      [[ -L "$CLAUDE_ROOT/output-styles/$name" \
         && "$(readlink "$CLAUDE_ROOT/output-styles/$name")" == "$f" ]] \
        || { err "Claude output style $name not linked to this repo"; style_missing=1; }
    else
      [[ -e "$CLAUDE_ROOT/output-styles/$name" || -L "$CLAUDE_ROOT/output-styles/$name" ]] \
        && rm -f "$CLAUDE_ROOT/output-styles/$name"
      ln -s "$f" "$CLAUDE_ROOT/output-styles/$name"; sn=$((sn+1))
    fi
  done
  (( CHECK )) && (( ! style_missing )) && ok "all Claude output styles linked"
  (( CHECK )) || ok "$sn Claude output styles linked (none selected)"
fi

if (( INSTALL_GUARD )); then
# Link the hook scripts individually too. Taking over ~/.claude/hooks would
# break any hook the user already wired there, and worse: settings.json keeps
# their entry, so a now-missing script makes python3 exit 2, and exit 2 in
# PreToolUse means BLOCK. Replacing the directory would turn their own hook
# into a block-everything rule.
(( CHECK )) || mkdir -p "$CLAUDE_ROOT/hooks"
hn=0
# guard*.py includes the host entry points and every module they import.
# Anything added here needs a matching --check assertion below.
for f in "$REPO"/hooks/guard*.py; do
  [[ -e "$f" ]] || continue
  base="$(basename "$f")"
  if (( CHECK )); then
    [[ -L "$CLAUDE_ROOT/hooks/$base" && "$(readlink "$CLAUDE_ROOT/hooks/$base")" == "$f" ]] \
      || err "hook $base not linked to this repo"
  else
    if [[ -L "$CLAUDE_ROOT/hooks/$base" && "$(readlink "$CLAUDE_ROOT/hooks/$base")" == "$f" ]]; then
      : # already ours
    elif [[ -e "$CLAUDE_ROOT/hooks/$base" || -L "$CLAUDE_ROOT/hooks/$base" ]]; then
      rm -f "$CLAUDE_ROOT/hooks/$base"
    fi
    ln -sfn "$f" "$CLAUDE_ROOT/hooks/$base"; hn=$((hn+1))
  fi
done
prune_stale "$CLAUDE_ROOT/hooks" hooks hooks
(( CHECK )) || ok "$hn hook scripts linked into ~/.claude/hooks (your own are untouched)"

# settings.json also holds the user's model, theme, and permissions, so it is
# merged rather than replaced. The `test -f` prefix means that deleting this
# repo degrades to "no guardrails" instead of blocking every tool call: a
# missing script makes python3 exit 2, and exit 2 in PreToolUse means BLOCK.
SETTINGS="$CLAUDE_ROOT/settings.json"
if (( GUARD_READY && ! CHECK )); then
  # One copy, once, before the first change. Not per-run: repeated installs
  # used to pile up identical backups.
  # `! already_managed`: on a machine with no settings.json, install #1 CREATES
  # it and correctly takes no backup, so install #2 saw a file with no backup
  # sibling and copied the already-modified file under a name that says
  # "before". The recovery copy contained our own hooks and deny rules.
  if [[ -f "$SETTINGS" && ! -e "$SETTINGS.before-onbelay" ]] \
     && ! grep -q 'onbelay-hook-v1' "$SETTINGS" 2>/dev/null; then
    cp "$SETTINGS" "$SETTINGS.before-onbelay"
    detail_warn "settings.json copied to settings.json.before-onbelay"
  fi
  # The merge lives in scripts/install_settings.py, with a test suite that
  # runs in milliseconds. It was 115 lines of Python inside this heredoc,
  # reachable only by running a real install into a fake HOME.
  python3 "$REPO/scripts/install_settings.py" merge "$SETTINGS" "$CLAUDE_ROOT/hooks"
  ok "settings.json PreToolUse hooks (existing keys preserved)"
elif (( GUARD_READY )); then
  # The same test the merge uses. A substring match called a hook that merely
  # MENTIONS the path "wired", and it never looked at the file matcher at all,
  # so --check said "all good" on a HOME with no guardrails running.
  python3 "$REPO/scripts/install_settings.py" check "$SETTINGS" "$CLAUDE_ROOT/hooks" \
    && ok "settings.json guard hooks" || err "settings.json guard hooks missing or not wired"
fi
fi

(( INSTALL_BASELINE )) && route_instructions "$CLAUDE_ROOT/CLAUDE.md"

# ---------------------------------------------------------------------- codex
section "Codex"
if [[ -d "$CODEX_ROOT" ]] || (( INSTALL_WORKFLOW )); then
  if (( INSTALL_WORKFLOW || INSTALL_OPERATOR )); then
  # Codex owns ~/.codex/skills: it preinstalls its own .system skills there,
  # so link each skill individually instead of replacing the directory.
  # A dotfile-managed symlink here gets the same treatment as the Claude side:
  # record the target and stand a real directory up. Without this, install
  # dropped one symlink per skill straight into the user's stow tree and
  # uninstall could never clean them out.
  (( CHECK )) || mkdir -p "$CODEX_ROOT/skills"
  n=0; missing=0
  for root in "${SKILL_ROOTS[@]}"; do
    for d in "$root"/*/; do
      [[ -f "$d/SKILL.md" ]] || continue
      name="$(basename "$d")"
      if (( CHECK )); then
        if [[ -L "$CODEX_ROOT/skills/$name" && "$(readlink "$CODEX_ROOT/skills/$name")" == "$d" ]]; then
          :
        elif [[ -f "$CODEX_ROOT/skills/$name/SKILL.md" ]]; then
          warn "codex skill $name is provided by an existing installation"
        else
          err "codex skill $name missing"; missing=1
        fi
      else
        kept_skill_conflict "$CODEX_ROOT/skills/$name" && continue
        if [[ -L "$CODEX_ROOT/skills/$name" && "$(readlink "$CODEX_ROOT/skills/$name")" == "$d" ]]; then
          : # already ours
        elif [[ -L "$CODEX_ROOT/skills/$name" && ! -e "$CODEX_ROOT/skills/$name" ]]; then
          rm "$CODEX_ROOT/skills/$name"
        elif [[ -e "$CODEX_ROOT/skills/$name" || -L "$CODEX_ROOT/skills/$name" ]]; then
          if _is_our_target "$(readlink "$CODEX_ROOT/skills/$name" 2>/dev/null || true)"; then
            rm -f "$CODEX_ROOT/skills/$name"
          else
            continue
          fi
        fi
        ln -sfn "$d" "$CODEX_ROOT/skills/$name"; n=$((n+1))
      fi
    done
  done
  prune_selected_skills "$CODEX_ROOT/skills"
  (( CHECK )) && (( ! missing )) && ok "all skills linked into ~/.codex/skills"
  (( CHECK )) || ok "$n skills linked into ~/.codex/skills"
  (( INSTALL_BASELINE )) && route_instructions "$CODEX_ROOT/AGENTS.md"
  fi

  if (( INSTALL_GUARD )); then
    CODEX_HOOKS="$CODEX_ROOT/hooks.json"
    if (( GUARD_READY && ! CHECK )); then
      # Same reasoning as the settings.json copy above.
      if [[ -f "$CODEX_HOOKS" && ! -e "$CODEX_HOOKS.before-onbelay" ]] \
         && ! grep -q 'guard-codex.py' "$CODEX_HOOKS" 2>/dev/null; then
        cp "$CODEX_HOOKS" "$CODEX_HOOKS.before-onbelay"
        detail_warn "hooks.json copied to hooks.json.before-onbelay"
      fi
      python3 "$REPO/scripts/install_codex_hooks.py" merge "$CODEX_HOOKS" "$REPO" \
        || die "could not merge onbelay hooks into $CODEX_HOOKS"
      ok "hooks.json PreToolUse guard merged (existing hooks preserved)"
      detail_warn "review and trust new or changed Codex hooks with /hooks."
    elif (( GUARD_READY )); then
      # A deleted Codex hook must not report "all good".
      if python3 "$REPO/scripts/install_codex_hooks.py" check "$CODEX_HOOKS" "$REPO"; then
        ok "codex hooks.json guard parity"
      else
        err "codex hooks.json missing, unparseable, or missing the onbelay guard"
      fi
      # Trust is keyed to each current hook definition and is intentionally not
      # inferred from private config internals. /hooks is the supported view.
      detail_warn "hook trust is user-reviewed state; inspect it with /hooks."
    fi
  fi
else
  warn "no ~/.codex, skipping Codex operator or guard wiring"
fi

# Everything above proves WIRING: the symlink exists, it points into this repo,
# settings.json names it. None of that survives a rule module that fails to
# import, and that state is invisible from the outside: the hook records a
# fail-open, exits 0, and --check still reported "Guard active" on a machine
# that would have accepted a force push to a protected branch.
#
# ONE PROBE PER RULE MODULE, not one probe. A single payload proved only the
# module that answers it: neutering the git rules or the credential rules left
# every assertion here passing and the check reporting all good. Each payload
# below is answered by a different module, so a module that stops deciding is
# named rather than masked by a neighbour.
#
# The allow case is not decoration. A guard that refuses everything is broken
# too, and only an allow can tell the two apart.
if (( INSTALL_GUARD && GUARD_READY )); then
  GUARD_HOOK="$CLAUDE_ROOT/hooks/guard-bash.py"
  # cwd is "/" so no verdict depends on the git state of wherever this ran, and
  # payloads are inlined into JSON, so none may contain a quote or a backslash.
  guard_verdict() {  # guard_verdict <command> -> the hook's exit status
    local rc=0
    printf '{"tool_name":"Bash","tool_input":{"command":"%s"},"cwd":"/"}' "$1" \
      | python3 "$GUARD_HOOK" >/dev/null 2>&1 || rc=$?
    echo "$rc"
  }
  if [[ ! -f "$GUARD_HOOK" ]]; then
    err "guard-bash.py is missing, so the guard cannot be proven to decide"
  else
    guard_live=1
    while IFS='|' read -r module payload; do
      [[ -n "$module" ]] || continue
      rc="$(guard_verdict "$payload")"
      if [[ "$rc" != 2 ]]; then
        err "the guard did NOT refuse '$payload' (hook exit $rc). Its $module rules are not protecting this machine."
        guard_live=0
      fi
    done <<'PROBES'
filesystem|rm -rf /
git|git push --force origin main
credential|cat ~/.aws/credentials
database|psql -h db.prod.example.com
PROBES
    allowed="$(guard_verdict 'git status')"
    if [[ "$allowed" != 0 ]]; then
      err "the guard refused 'git status' (hook exit $allowed). It would block ordinary work."
    elif (( guard_live )); then
      ok "guard proven live: refuses filesystem, git, credential and database shapes, allows 'git status'"
    fi
  fi
  # A narrowed or emptied branch list is a legitimate choice and a quiet one,
  # so say it out loud rather than letting a user forget they made it.
  if [[ -n "${ONBELAY_PROTECTED_BRANCHES+set}" ]]; then
    if [[ -z "$ONBELAY_PROTECTED_BRANCHES" ]]; then
      warn "ONBELAY_PROTECTED_BRANCHES is empty: the protected-branch rules are OFF."
    else
      warn "ONBELAY_PROTECTED_BRANCHES is set, so the protected branches are: $ONBELAY_PROTECTED_BRANCHES"
    fi
  fi
  # The signal already existed and nothing ever surfaced it. A non-empty log
  # means the guard has gone quiet at least once on this machine.
  if [[ -s "$CLAUDE_ROOT/guard-failopen.log" ]]; then
    warn "$CLAUDE_ROOT/guard-failopen.log is not empty: the guard has failed open before. Read it."
  fi
fi

# Measured, not asserted. A same-name skill the user already had is KEPT by
# design, but that means ours is NOT the one running, and the banner claimed
# 13/13 regardless: --check printed it and exited 0 on a HOME where none of
# ours was installed. Same defect the guard banner had.
workflow_active() {
  local n=0 s
  for s in "${WORKFLOW_SKILLS[@]}"; do
    [[ -L "$CLAUDE_ROOT/skills/$s" ]] \
      && _is_our_target "$(readlink "$CLAUDE_ROOT/skills/$s")" \
      && n=$((n+1))
  done
  echo "$n"
}
report_workflow() {
  local have total="${#WORKFLOW_SKILLS[@]}"
  have="$(workflow_active)"
  if [[ "$have" == "$total" ]]; then
    status "Workflow active: $have/$total"
  else
    warn "Workflow active: $have/$total (the rest are skills you already had)"
  fi
}

# The superseded 0.3.x payload. Left behind, it is a second copy of the product
# that `doctor` still finds through the migrated origins file, so the machine
# keeps reporting a version it no longer runs. Only ever a staged payload, never
# a user's clone, because a clone is never under this path. A link still
# pointing in means the relink above did not adopt everything, and removing it
# would break what is still running.
LEGACY_PAYLOAD="$HOME/.local/share/agent-config"
if (( ! CHECK )) && [[ -d "$LEGACY_PAYLOAD" ]]; then
  if find "$CLAUDE_ROOT" "$CODEX_ROOT" -maxdepth 3 -type l \
       -lname "$LEGACY_PAYLOAD/*" 2>/dev/null | grep -q .; then
    warn "kept $LEGACY_PAYLOAD: something still links into it"
  else
    rm -rf "$LEGACY_PAYLOAD" && ok "removed the superseded agent-config payload"
  fi
fi

(( COMPACT )) || echo
if (( CHECK )); then
  if (( PROBLEMS )); then
    # The npx CLI takes a profile positionally, except `full`, which it spells
    # `--extras`, and `standard`, which is its default.
    case "$PROFILE" in
      full)     _fix_flag=" --extras" ;;
      standard) _fix_flag="" ;;
      *)        _fix_flag=" $PROFILE" ;;
    esac
    # ONBELAY_COMPACT is set by bin/onbelay.js and by nothing else,
    # so it is already the answer to "how did this user install". Printing
    # `./install.sh` at an npx user names a file they do not have, and it was
    # on EVERY non-clean doctor run.
    if (( COMPACT )); then
      echo "Check complete: $PROBLEMS problem(s). Run: npx @sid-thephysicskid/onbelay@latest install${_fix_flag} to fix."
    else
      echo "Check complete: $PROBLEMS problem(s). Run ./install.sh $PROFILE to fix."
    fi
    exit 1
  fi
  if [[ "$PROFILE" == standard || "$PROFILE" == full ]]; then
    status "Guard active"
    report_workflow
    status "Claude Code + Codex routing active"
  else
    echo "Check complete: all good."
  fi
else
  if [[ "$PROFILE" == standard || "$PROFILE" == full ]]; then
    status "Guard active"
    report_workflow
    status "Claude Code + Codex routing active"
    warn "Restart your agent, then review Codex hooks with /hooks"
  elif [[ "$PROFILE" == guard ]]; then
    echo "Done. Review hook trust in each host, then start a new agent session."
  elif [[ "$PROFILE" == workflow ]]; then
    echo "Done. Start a new agent session to pick up the workflow skills."
  elif [[ "$PROFILE" == operator ]]; then
    echo "Done. Start a new agent session to pick up the optional operator tools."
  else
    echo "Done. Review hook trust, then start a new agent session."
  fi
  (( COMPACT )) || echo "To remove: $REPO/uninstall.sh"
fi

exit 0
