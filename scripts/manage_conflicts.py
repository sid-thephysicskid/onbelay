#!/usr/bin/env python3
"""Back up installer conflicts and restore them on uninstall."""

import json
import os
import shutil
import sys
import tempfile
import uuid


def lexists(path):
    return os.path.lexists(path)


def load(path):
    if not lexists(path):
        return []
    if os.path.islink(path) or not os.path.isfile(path):
        raise ValueError("conflict state is not a regular file")
    with open(path, encoding="utf-8") as fh:
        value = json.load(fh)
    if not isinstance(value, list):
        raise ValueError("conflict state is not a list")
    return value


def save(path, entries):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".onbelay-conflicts-", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fd = -1
            json.dump(entries, fh, indent=2)
            fh.write("\n")
        os.replace(temporary, path)
        temporary = None
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary:
            os.unlink(temporary)


def backup(state, paths):
    entries = load(state)
    known = {entry["path"] for entry in entries}
    root = state + ".d"
    if lexists(root) and (os.path.islink(root) or not os.path.isdir(root)):
        raise ValueError("conflict backup directory is not a regular directory")
    moved = []
    try:
        for path in paths:
            if path in known or not lexists(path):
                continue
            os.makedirs(root, exist_ok=True)
            destination = os.path.join(root, uuid.uuid4().hex)
            os.rename(path, destination)
            entry = {"path": path, "backup": destination}
            entries.append(entry)
            moved.append(entry)
        save(state, entries)
    except Exception:
        for entry in reversed(moved):
            if lexists(entry["backup"]) and not lexists(entry["path"]):
                os.rename(entry["backup"], entry["path"])
        raise


def restore(state):
    entries = load(state)
    remaining = []
    for entry in reversed(entries):
        path, saved = entry["path"], entry["backup"]
        if not lexists(saved):
            continue
        if lexists(path):
            remaining.append(entry)
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.rename(saved, path)
    if remaining:
        save(state, list(reversed(remaining)))
    else:
        try:
            os.unlink(state)
        except FileNotFoundError:
            pass
        shutil.rmtree(state + ".d", ignore_errors=True)


def main(argv):
    if len(argv) < 3:
        return 2
    if argv[1] == "backup" and len(argv) > 3:
        backup(argv[2], argv[3:])
        return 0
    if argv[1] == "restore" and len(argv) == 3:
        restore(argv[2])
        return 0
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
