#!/usr/bin/env python3
"""Add, check, or remove On Belay's bounded instruction block."""

import os
import sys
import tempfile


START = "<!-- onbelay:start -->"
END = "<!-- onbelay:end -->"


def target(path):
    return os.path.realpath(path) if os.path.islink(path) else path


def block(source):
    with open(source, encoding="utf-8") as fh:
        body = fh.read().strip()
    return f"{START}\n{body}\n{END}"


def read_text(path):
    """Verbatim. The default read translates newlines, so merging a routing
    block into a CRLF instruction file rewrote every line ending in it."""
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def restore_eol(text, original):
    """Give text back the newline convention the file was already using."""
    return text.replace("\n", "\r\n") if "\r\n" in original else text


def split_managed(text):
    if START not in text and END not in text:
        return text, None
    if text.count(START) != 1 or text.count(END) != 1:
        raise ValueError("instruction file has malformed onbelay markers")
    before, rest = text.split(START, 1)
    _managed, after = rest.split(END, 1)
    return before + after, True


def save(path, text):
    destination = target(path)
    directory = os.path.dirname(destination) or "."
    os.makedirs(directory, exist_ok=True)
    mode = os.stat(destination).st_mode & 0o777 if os.path.exists(destination) else 0o644
    fd, temporary = tempfile.mkstemp(prefix=".onbelay-instructions-", dir=directory)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fd = -1
            fh.write(text)
        os.replace(temporary, destination)
        temporary = None
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary:
            os.unlink(temporary)


def merge(path, source):
    destination = target(path)
    original = ""
    if os.path.exists(destination):
        if not os.path.isfile(destination):
            raise ValueError(f"{path} is not a regular file")
        original = read_text(destination)
    clean, _had = split_managed(original.replace("\r\n", "\n"))
    rendered = restore_eol(clean + block(source), original)
    if rendered == original:
        return
    save(path, rendered)


def check(path, source):
    destination = target(path)
    if not os.path.isfile(destination):
        return False
    text = read_text(destination).replace("\r\n", "\n")
    try:
        _clean, had = split_managed(text)
    except ValueError:
        return False
    return bool(had and block(source) in text)


def strip(path):
    destination = target(path)
    if not os.path.isfile(destination):
        return
    original = read_text(destination)
    clean, had = split_managed(original.replace("\r\n", "\n"))
    if not had:
        return
    save(path, restore_eol(clean, original))


def validate(path):
    destination = target(path)
    if not os.path.exists(destination):
        return
    if not os.path.isfile(destination):
        raise ValueError(f"{path} is not a regular file")
    split_managed(read_text(destination).replace("\r\n", "\n"))


def main(argv):
    if len(argv) < 3 or argv[1] not in {"merge", "check", "strip", "validate"}:
        print("usage: manage_instructions.py merge|check|strip|validate PATH [SOURCE]", file=sys.stderr)
        return 2
    action, path = argv[1:3]
    if action in {"strip", "validate"}:
        {"strip": strip, "validate": validate}[action](path)
        return 0
    if len(argv) != 4:
        return 2
    if action == "merge":
        merge(path, argv[3])
        return 0
    return 0 if check(path, argv[3]) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
