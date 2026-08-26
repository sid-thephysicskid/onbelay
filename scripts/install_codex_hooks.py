#!/usr/bin/env python3
"""Merge onbelay hooks into Codex hooks.json without taking it over.

    install_codex_hooks.py merge <path> <repo>
    install_codex_hooks.py strip <path>
    install_codex_hooks.py check <path> <repo>
    install_codex_hooks.py validate <path>

The file belongs to the user. Merge preserves unrelated keys and hooks. Strip
removes only handlers written by this module.
"""
import json
import os
import re
import shlex
import sys
import tempfile


DESCRIPTION = "PreToolUse guardrails from onbelay"
LEGACY_DESCRIPTIONS = {
    "Guardrails shared with Claude Code via onbelay/hooks",
    "Lifecycle hooks shared with Claude Code via onbelay/hooks",
}
LEGACY_SCRIPTS = {"guard-codex.py", "check-docs.py", "welcome.py"}
WIRING = (
    ("PreToolUse", ".*", "guard-codex.py", 5, "Checking guardrails..."),
)
_COMMAND_TAG = "onbelay-hook-v1"
_OUR_COMMAND = re.compile(
    r"^: " + re.escape(_COMMAND_TAG) + r":([\w.-]+); if test -f (.+); "
    r"then exec python3 \2; fi; exit 0$")
_LEGACY_COMMAND = re.compile(
    r"^if test -f '([^']+)/hooks/([\w.-]+)'; then exec python3 "
    r"'\1/hooks/\2'; fi; exit 0$")
_WIRING_BY_EVENT = {
    event: (matcher, script, timeout, status)
    for event, matcher, script, timeout, status in WIRING
}


def _command(repo, script):
    path = "%s/hooks/%s" % (repo.rstrip("/"), script)
    quoted = shlex.quote(path)
    return ": %s:%s; if test -f %s; then exec python3 %s; fi; exit 0" % (
        _COMMAND_TAG, script, quoted, quoted)


def _legacy_command(repo, script):
    path = "%s/hooks/%s" % (repo.rstrip("/"), script)
    return "if test -f '%s'; then exec python3 '%s'; fi; exit 0" % (path, path)


def our_script(command):
    found = _OUR_COMMAND.match(str(command).strip())
    if found:
        return found.group(1)
    return None


def _owned_handler(event, group, handler, legacy):
    command = str(handler.get("command", "")).strip()
    # The tag is an ownership marker, including for hooks retired by a newer
    # release. Restricting removal to current WIRING left old lifecycle hooks
    # running forever after the product stopped shipping them.
    if our_script(command):
        return True
    old = _LEGACY_COMMAND.match(command)
    if legacy and old and old.group(2) in LEGACY_SCRIPTS:
        return True
    wiring = _WIRING_BY_EVENT.get(event)
    if wiring is None:
        return False
    matcher, script, timeout, status = wiring
    if group.get("matcher") != matcher:
        return False
    if handler.get("type") != "command" \
       or handler.get("timeout") != timeout \
       or handler.get("statusMessage") != status:
        return False
    return False


def _validate(cfg):
    if not isinstance(cfg, dict):
        raise ValueError("hooks.json is not a JSON object")
    hooks = cfg.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("hooks.json hooks is not a JSON object")
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            raise ValueError("hooks.json hooks.%s is not a list" % event)
        for group in groups:
            if not isinstance(group, dict):
                raise ValueError("hooks.json contains a non-object matcher group")
            handlers = group.get("hooks", [])
            if not isinstance(handlers, list):
                raise ValueError("hooks.json matcher hooks is not a list")
            if not all(isinstance(handler, dict) for handler in handlers):
                raise ValueError("hooks.json contains a non-object hook handler")
    return cfg


def _load(path):
    path = os.path.realpath(path) if os.path.islink(path) else path
    if not os.path.exists(path):
        return {}, False
    with open(path) as f:
        return _validate(json.load(f)), True


def _save(cfg, path):
    path = os.path.realpath(path) if os.path.islink(path) else path
    rendered = json.dumps(cfg, indent=2) + "\n"
    try:
        with open(path) as f:
            if f.read() == rendered:
                return
    except OSError:
        pass
    mode = None
    try:
        mode = os.stat(path, follow_symlinks=False).st_mode & 0o777
    except FileNotFoundError:
        pass
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".", dir=directory)
    try:
        if mode is not None:
            os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as f:
            fd = -1
            f.write(rendered)
        os.replace(tmp, path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _remove_ours(cfg):
    events = cfg.get("hooks", {})
    legacy = cfg.get("description") in LEGACY_DESCRIPTIONS
    for event, groups in list(events.items()):
        for group in groups:
            group["hooks"] = [
                handler for handler in group.get("hooks", [])
                if not _owned_handler(event, group, handler, legacy)
            ]
        groups[:] = [group for group in groups if group.get("hooks")]
        if not groups:
            del events[event]
    if not events and "hooks" in cfg:
        del cfg["hooks"]


def merge(path, repo):
    cfg, existed = _load(path)
    _remove_ours(cfg)
    events = cfg.setdefault("hooks", {})
    for event, matcher, script, timeout, status in WIRING:
        handler = {
            "type": "command",
            "command": _command(repo, script),
            "timeout": timeout,
            "statusMessage": status,
        }
        group = {"hooks": [handler]}
        if matcher is not None:
            group["matcher"] = matcher
        events.setdefault(event, []).append(group)
    if cfg.get("description") in LEGACY_DESCRIPTIONS:
        cfg["description"] = DESCRIPTION
    elif not existed and "description" not in cfg:
        cfg["description"] = DESCRIPTION
    _save(cfg, path)


def strip(path):
    if not os.path.exists(path):
        return
    cfg, _existed = _load(path)
    _remove_ours(cfg)
    if cfg.get("description") in LEGACY_DESCRIPTIONS | {DESCRIPTION}:
        del cfg["description"]
    if not cfg and not os.path.islink(path):
        os.unlink(path)
    else:
        _save(cfg, path)


def check(path, repo):
    cfg, existed = _load(path)
    if not existed:
        return False
    for event, matcher, script, timeout, status in WIRING:
        wanted = _command(repo, script)
        found = False
        for group in cfg.get("hooks", {}).get(event, []):
            if group.get("matcher") != matcher:
                continue
            if any(handler.get("type") == "command"
                   and handler.get("command") == wanted
                   and handler.get("timeout") == timeout
                   and handler.get("statusMessage") == status
                   for handler in group.get("hooks", [])):
                found = True
                break
        if not found:
            return False
    return True


def main(argv):
    if len(argv) == 4 and argv[1] in ("merge", "check"):
        if argv[1] == "merge":
            merge(argv[2], argv[3])
            return 0
        return 0 if check(argv[2], argv[3]) else 1
    if len(argv) == 3 and argv[1] == "strip":
        strip(argv[2])
        return 0
    if len(argv) == 3 and argv[1] == "validate":
        _load(argv[2])
        return 0
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
