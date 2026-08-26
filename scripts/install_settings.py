#!/usr/bin/env python3
"""Merge this repo's hooks and deny rules into ~/.claude/settings.json.

    install_settings.py merge <path>    wire us in, preserving everything else
    install_settings.py strip <path>    remove exactly what merge added
    install_settings.py validate <path> validate without changing the file
    install_settings.py deny            print the deny rules, one per line

Lived as a 115-line heredoc inside install.sh, where it could only be exercised
through a five-minute bash suite, and where the same "find this event's entry,
drop any command that runs one of our scripts, append ours" appeared three
times with three separate regexes.

**settings.json is the user's file.** It holds their model, theme and
permissions. Every operation here is additive or exactly-reversing: we replace
our own entries, never theirs, and a rule the user added by hand survives a
strip. The write is tmp-then-rename, so a crash cannot truncate it.

Python 3.9, stdlib only, no network.
"""
import json
import os
import re
import shlex
import stat
import sys
import tempfile

# One place, used by merge and strip. Two hand-kept copies in two shell scripts
# is what `tests/audit.py` had to assert about, and that assertion goes away
# with the duplication.
#
# Deliberately SHORT, for two measured reasons rather than caution:
#
# 1. A deny rule cannot carve out an exception. `git push --force-with-lease`
#    is sanctioned by /ship step 9, so no force-push rule can live here at all.
#    The hook keeps that one, because only it can tell the two apart.
# 2. A deny rule cannot enumerate flag permutations. `Bash(git clean -fd:*)`
#    was in this list and did not stop `git clean -df`, the same command.
#    Anything whose danger lives in a short-flag cluster belongs to the hook,
#    which parses the cluster instead of matching it.
#
# What is left is what declarative rules do better than a program: PATHS, where
# a glob is exact and total, plus the one long-flag command with no variants.
# The host enforces these in every mode including bypassPermissions, and unlike
# the hook they cannot fail open.
DENY = (
    "Bash(git reset --hard:*)",
    "Read(**/.env)",
    "Read(**/.env.local)",
    "Read(**/.env.production)",
    "Read(**/id_rsa)",
    "Read(**/id_ed25519)",
    "Read(**/.pgpass)",
    "Read(**/.netrc)",
    "Write(~/.claude/hooks/**)",
)

_GUARD = "if test -f ~/.claude/hooks/%s; then exec python3 ~/.claude/hooks/%s; fi; exit 0"
_COMMAND_TAG = "onbelay-hook-v1"
_TAGGED = re.compile(r"^: " + re.escape(_COMMAND_TAG) + r":([\w.-]+); ")


def _cmd(script, hook_dir=None):
    if hook_dir is None:
        return _GUARD % (script, script)
    path = shlex.quote(os.path.join(hook_dir, script))
    return ": %s:%s; if test -f %s; then exec python3 %s; fi; exit 0" % (
        _COMMAND_TAG, script, path, path)


# event, matcher, script, timeout. This product installs blocking PreToolUse
# guards only. Lifecycle coaching belongs in the optional workflow pack, not in
# a heuristic hook that can trap an agent after otherwise valid work.
WIRING = (
    ("PreToolUse", "Bash", "guard-bash.py", 5),
    ("PreToolUse", "Read|Edit|Write|MultiEdit|NotebookEdit|mcp__.*__(read.*|view.*|write.*|edit.*|move.*|rename.*|delete.*|remove.*|create.*|apply.*)", "guard-files.py", 5),
)

# Does this command actually EXECUTE one of our scripts? A plain substring test
# also deleted a user hook that merely mentions the path, such as
# `python3 ~/mine/wrap.py --after hooks/guard-files.py`, and a match on
# "guard-" removed someone's `my-guard-check.sh` permanently.
_OURS = re.compile(
    r"python3?\s+\S*[./]claude/hooks/"
    r"(guard-(bash|files)|check-docs|welcome)\.py(\s|;|$)")


def runs_ours(command):
    return bool(_OURS.search(str(command)) or _TAGGED.match(str(command).strip()))


# The exact shape install writes, with any script name. `runs_ours` also knows
# retired script names so upgrades can remove them. This template recognizes
# any entry we wrote, including a future retired name.
_OUR_SHAPE = re.compile(
    r"^if test -f ~/\.claude/hooks/([\w.-]+); then exec python3 "
    r"~/\.claude/hooks/\1; fi; exit 0$")

_DENY_STATE_SUFFIX = ".onbelay-deny.json"


def our_hook_script(command):
    """The script name if we wrote this hook entry, else None."""
    text = str(command).strip()
    found = _OUR_SHAPE.match(text)
    if found:
        return found.group(1)
    tagged = _TAGGED.match(text)
    return tagged.group(1) if tagged else None


def _target(path):
    return os.path.realpath(path) if os.path.islink(path) else path


def _load(path):
    path = _target(path)
    cfg = {}
    if os.path.exists(path):
        with open(path) as f:
            cfg = json.load(f)
    if not isinstance(cfg, dict):
        raise SystemExit("settings.json is not a JSON object")
    return cfg


def _validate(cfg):
    """Reject every shape that merge or strip would have to guess about."""
    hooks = cfg.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("hooks is not an object")
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            raise ValueError("hooks.%s is not a list" % event)
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("a hooks.%s entry is not an object" % event)
            inner = entry.get("hooks", [])
            if not isinstance(inner, list):
                raise ValueError("a hooks.%s entry's hooks is not a list" % event)
            if any(not isinstance(hook, dict) for hook in inner):
                raise ValueError("a hook inside hooks.%s is not an object" % event)
    permissions = cfg.get("permissions", {})
    if not isinstance(permissions, dict):
        raise ValueError("permissions is not an object")
    if "deny" in permissions and not isinstance(permissions["deny"], list):
        raise ValueError("permissions.deny is not a list")


def _deny_state_path(path):
    return _target(path) + _DENY_STATE_SUFFIX


def _load_managed_denies(path):
    state = _deny_state_path(path)
    if not os.path.lexists(state):
        return []
    if os.path.islink(state) or not os.path.isfile(state):
        raise ValueError("managed deny state is not a regular file")
    with open(state) as f:
        managed = json.load(f)
    if (not isinstance(managed, list)
            or any(not isinstance(rule, str) or rule not in DENY
                   for rule in managed)):
        raise ValueError("managed deny state is invalid")
    return managed


def validate(path):
    _validate(_load(path))
    _load_managed_denies(path)


def _save(cfg, path):
    # tmp-then-rename: a crash mid-write must not leave a truncated
    # settings.json, which the agent would then start with no hooks at all.
    path = _target(path)
    mode = stat.S_IMODE(os.stat(path).st_mode) if os.path.exists(path) else 0o600
    directory = os.path.dirname(os.path.abspath(path))
    prefix = ".%s.tmp-" % os.path.basename(path)
    fd, tmp = tempfile.mkstemp(prefix=prefix, dir=directory)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as f:
            fd = -1
            json.dump(cfg, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
        tmp = None
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass


def _entries(cfg, event):
    return cfg.setdefault("hooks", {}).setdefault(event, [])


def wire(cfg, event, matcher, script, timeout, hook_dir=None):
    """Put our hook on this event, replacing any earlier version of ours.

    Never duplicates and never touches a hook that is not ours. This was three
    copies with three regexes; a rename used to need editing in all of them.
    """
    entries = _entries(cfg, event)
    # A matcher can change across releases. Remove this exact script from its
    # previous entry first, or an upgrade runs both the stale and new hook.
    for candidate in entries:
        candidate["hooks"] = [
            hook for hook in candidate.get("hooks", [])
            if not (our_hook_script(hook.get("command", "")) == script
                    or (runs_ours(hook.get("command", ""))
                        and script in hook.get("command", "")))
        ]
    entries[:] = [candidate for candidate in entries if candidate.get("hooks")]
    if matcher is not None:
        entry = next((e for e in entries if e.get("matcher") == matcher), None)
    else:
        entry = next((e for e in entries
                      if any(runs_ours(h.get("command", ""))
                             for h in e.get("hooks", []))), None)
    command = {"type": "command", "command": _cmd(script, hook_dir), "timeout": timeout}
    if entry is None:
        new = {"hooks": [command]}
        if matcher is not None:
            new = {"matcher": matcher, "hooks": [command]}
        entries.append(new)
        return
    entry.setdefault("hooks", []).append(command)


def prune(cfg):
    """Drop hooks WE wrote that name a script this repo no longer ships.

    install.sh prunes stale skill symlinks; nothing pruned settings.json, so a
    hook dropped from WIRING stayed wired on every machine that had installed
    it. The `test -f` guard degrades that to a no-op rather than a broken
    session, which is exactly why it would sit there unnoticed.

    Ownership is decided by the command's shape, not by `runs_ours`: that is a
    list of names, so a script stops being recognised as ours on the day it is
    removed, which is the one day it has to be.
    """
    keep = {script for _e, _m, script, _t in WIRING}
    events = cfg.get("hooks") or {}
    for event, entries in list(events.items()):
        for entry in entries:
            inner = entry.get("hooks") or []
            inner[:] = [h for h in inner
                        if (our_hook_script(h.get("command", "")) or "*") in keep
                        or our_hook_script(h.get("command", "")) is None]
        entries[:] = [e for e in entries if e.get("hooks")]
        if not entries:
            del events[event]


def merge(path, hook_dir=None):
    cfg = _load(path)
    _validate(cfg)
    managed = _load_managed_denies(path)
    prune(cfg)
    for event, matcher, script, timeout in WIRING:
        wire(cfg, event, matcher, script, timeout, hook_dir)
    deny = cfg.setdefault("permissions", {}).setdefault("deny", [])
    for rule in DENY:
        if rule not in deny:
            deny.append(rule)
            if rule not in managed:
                managed.append(rule)
    _save(cfg, path)
    # The separate ledger lets strip distinguish our additions from an
    # identical rule the user already had. If writing it ever fails, uninstall
    # conservatively leaves the rule rather than weakening their policy.
    _save(managed, _deny_state_path(path))


def strip(path):
    """Remove exactly what merge added, and nothing else."""
    if not os.path.exists(path):
        return
    cfg = _load(path)
    _validate(cfg)
    managed = set(_load_managed_denies(path))
    # Leaving the rule is the right call: without the ledger it cannot be told
    # apart from an identical rule the user wrote. Saying nothing is not. A lost
    # sidecar, which is an untracked file next to settings.json and easy to drop
    # in a restore, made uninstall leave every deny rule while reporting that
    # configuration was preserved and the guard removed.
    perms_now = cfg.get("permissions")
    present = perms_now.get("deny") if isinstance(perms_now, dict) else None
    orphaned = [r for r in (present or []) if r in DENY and r not in managed]
    if orphaned:
        sys.stderr.write(
            "leaving %d deny rule(s) in %s: the ownership record is missing, so "
            "they cannot be told apart from rules you added yourself. Remove by "
            "hand if you want them gone:\n%s\n"
            % (len(orphaned), path, "\n".join("  " + r for r in orphaned)))
    for event in {e for e, _m, _s, _t in WIRING}:
        entries = cfg.get("hooks", {}).get(event, [])
        for entry in entries:
            entry["hooks"] = [h for h in entry.get("hooks", [])
                              if not runs_ours(h.get("command", ""))]
        kept = [e for e in entries if e.get("hooks")]
        if kept:
            cfg["hooks"][event] = kept
        elif event in cfg.get("hooks", {}):
            del cfg["hooks"][event]
    if "hooks" in cfg and not cfg["hooks"]:
        del cfg["hooks"]
    perms = cfg.get("permissions")
    if isinstance(perms, dict) and isinstance(perms.get("deny"), list):
        perms["deny"] = [r for r in perms["deny"] if r not in managed]
        if not perms["deny"]:
            del perms["deny"]
        if not perms:
            del cfg["permissions"]
    _save(cfg, path)
    try:
        os.unlink(_deny_state_path(path))
    except FileNotFoundError:
        pass


def check(path, hook_dir=None):
    cfg = _load(path)
    _validate(cfg)
    for event, matcher, script, timeout in WIRING:
        wanted = _cmd(script, hook_dir)
        if not any(
            entry.get("matcher") == matcher
            and any(hook.get("command") == wanted and hook.get("timeout") == timeout
                    for hook in entry.get("hooks", []))
            for entry in cfg.get("hooks", {}).get(event, [])
        ):
            return False
    return True


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip())
        return 2
    action = argv[1]
    if action == "deny":
        print("\n".join(DENY))
        return 0
    if action in ("merge", "check") and len(argv) in (3, 4):
        hook_dir = argv[3] if len(argv) == 4 else None
        if action == "merge":
            merge(argv[2], hook_dir)
            return 0
        return 0 if check(argv[2], hook_dir) else 1
    if action in ("strip", "validate") and len(argv) == 3:
        {"strip": strip, "validate": validate}[action](argv[2])
        return 0
    print(__doc__.strip())
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
