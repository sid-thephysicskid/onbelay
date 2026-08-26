#!/usr/bin/env python3
"""Command-line parsing. Stdlib only, no policy.

Everything here answers "what is this command line",
never "is it allowed". Rules query Invocation rather than
re-deriving any of it.
"""
import os
import re
import shlex


# Every program that runs what it is handed, defined ONCE, as membership.
#
# Four hand-copied spellings of this list used to exist. The old comment here
# argued they must stay apart, and it conflated two different things: the
# MATCHERS genuinely must differ (exact basename in one place, alternation in
# another), but the MEMBERSHIP never should. They drifted, and each gap was a
# sibling spelling of an already-blocked command that was allowed instead:
# `bun -c`, `| ash`, `| busybox sh`, `| python2`.
#
# So: one set, and every matcher below is derived from it. Adding a runner in
# one place now adds it everywhere.

# `-c` takes a COMMAND LINE, which has to be re-split into segments.
SHELL_NAMES = frozenset(("sh", "bash", "zsh", "dash", "ksh", "ash", "busybox"))
# ...and `-c`/`-e` takes a PROGRAM. Kept apart from SHELL_NAMES because `;`
# means something different in each, not because the membership differs.
INTERPRETER_NAMES = frozenset(("python", "python2", "python3", "perl", "ruby",
                               "node", "deno", "bun"))
RUNNER_NAMES = SHELL_NAMES | INTERPRETER_NAMES


def _alt(names):
    """Alternation over names, longest first so no short name shadows a longer.

    Without the sort, `sh|...|bash` lets `sh` win inside `bash` wherever the
    pattern is not anchored, and the group then reports the wrong runner.
    """
    return "|".join(sorted((re.escape(n) for n in names), key=len, reverse=True))


# The alternation form, for the weaker question "is a runner named anywhere on
# this line". Exact-basename matching lives at the SHELL_NAMES use sites, where
# a loose match once let `ssh -c <cipher>` be read as a shell.
_RUNNERS = _alt(RUNNER_NAMES)

# `--help` prints documentation and runs nothing. This lives here rather than
# in a rule module because two of them need it and the import arrow between
# them only points one way: guard_tools imports guard_git, so guard_git can
# never import it back. A second copy is how the four spellings of
# RUNNER_NAMES drifted, and this is the same shape.
def asks_for_help(seg):
    """`--help` as a FLAG, or `git help <topic>`. Not as an ARGUMENT.

    Everything after `--` is an operand, not an option, so
    `git commit -m pwn -- --help` is a commit whose pathspec happens to be the
    string `--help`. A substring test for `--help` read that as documentation
    and handed back a free bypass of every rule in the file. The corpus pins
    it; the first spelling of this exemption failed that case, which is the
    whole reason the paired cases exist.
    """
    toks = tokens(seg)
    for tok in toks:
        if tok == "--":
            break
        if tok == "--help":
            return True
    # `git help rebase`. The subcommand position only: a bare `help` token
    # anywhere would match `git commit -m x -- git help`, which is the same
    # trap in a different spelling.
    for i, tok in enumerate(toks):
        if os.path.basename(tok) == "git":
            for nxt in toks[i + 1:]:
                if nxt.startswith("-"):
                    continue
                return nxt == "help"
    return False

# Commands whose arguments are prose or search patterns, not instructions.
# Applied PER SEGMENT.
# An `echo`/`printf` whose output feeds an interpreter is not prose. The SQL
# rules already handle the `| psql` shape; this is the same idea for shells.
_SHELL_HEAD = re.compile(
    # `(\S*/)?`, not `\S*`: the loose form also matched `ssh`, so `cat x | ssh
    # host` would have been read as piping into a local shell.
    r"^\s*(\S*/)?(" + _RUNNERS + r")\b")

# Shell words that wrap a real command. Without stripping these, `sudo git push
# --force` skipped every git rule.
# NOTE: xargs is deliberately NOT here. check_rm has a specific xargs rule, and
# git_invocations finds git by basename anywhere in the segment, so leaving
# xargs in place costs nothing and keeps `xargs rm -rf` detectable.
WRAPPERS = {"sudo", "env", "command", "builtin", "exec", "nohup", "time", "nice",
            "eval", "if", "while", "until", "then", "do", "else", "elif",
            "fi", "done", "!",
            # Same shape as nohup and nice: they run what they are handed.
            # `timeout` is the one people actually type, and its `-s`/`-k`
            # take VALUES, which is why _WRAPPER_VALUE_FLAGS is per-wrapper
            # rather than shared.
            "timeout", "stdbuf", "setsid", "flock", "doas", "torsocks",
            "chrt", "ionice", "unbuffer"}

# Flags a wrapper consumes a VALUE for, PER WRAPPER. Not one shared set: `-n`
# is an adjustment to nice and means non-interactive to sudo, so a shared set
# would eat the real command after `sudo -n` and open a fresh bypass while
# closing this one.
_WRAPPER_VALUE_FLAGS = {
    "sudo": {"-u", "-g", "-p", "-C", "-r", "-t", "-U", "--user", "--group"},
    "nice": {"-n", "--adjustment"},
    "env": {"-u", "-C", "--chdir", "--unset"},
    # `timeout -s TERM 30 cmd`: -s and -k each consume a value, and the
    # DURATION is a bare positional the stripper stops on, which is fine.
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
    "flock": {"-w", "--wait", "--timeout", "-E", "--conflict-exit-code"},
    "ionice": {"-c", "-n", "--class", "--classdata"},
    "chrt": {"-p", "--pid"},
}
_NEXT_TOKEN = re.compile(r"\s*(?P<tok>\S+)")


def strip_wrapper_prefix(text):
    """Drop leading wrapper words, their flags, and the values those consume.

    The loop this replaces stopped at the first flag, because a flag is
    neither a wrapper nor an assignment. So `sudo psql -h prod` was caught and
    `sudo -u postgres psql -h prod` was not: one flag between the wrapper and
    the binary disabled every rule anchored on the head of the command. The
    same hole hid `nice -n 10`, `sudo -H`, and the inline-program rules.

    Slices the ORIGINAL text rather than rejoining tokens, so quoting and
    inner spacing survive for the rules that read them.
    """
    i, saw, current = 0, False, None
    while True:
        m = _NEXT_TOKEN.match(text, i)
        if not m:
            break
        tok = m.group("tok")
        if tok in WRAPPERS:
            i, saw, current = m.end(), True, tok
            continue
        if "=" in tok and not tok.startswith("-"):
            i, saw = m.end(), True
            continue
        if not saw:
            break
        # Only AFTER a wrapper: a flag here belongs to the wrapper, because a
        # command's own flags cannot precede its name.
        if tok.startswith("-"):
            i = m.end()
            if tok in _WRAPPER_VALUE_FLAGS.get(current, ()):
                nxt = _NEXT_TOKEN.match(text, i)
                if nxt:
                    i = nxt.end()
            continue
        # `nice 10 cmd` is the flagless spelling of the adjustment.
        if current == "nice" and tok.isdigit():
            i = m.end()
            continue
        break
    return text[i:] if saw else text


# Beyond this, a "command" is file content rather than an instruction, and
# scanning all of it costs far more than it protects.
MAX_ANALYSED = 32 * 1024

TAIL_ANALYSED = 8 * 1024

MAX_SEGMENTS = 4000

# The list of things worth finding in the discarded middle used to live here,
# hand-copied from the rules. It went stale: sixteen blocked classes, every
# irreversible publish among them, were allowed once padded past the window.
# A parser cannot own that list without becoming a second, silent rule set, so
# each rule module now exports its own MIDDLE_SIGNALS and guard_rules joins
# them. This module went back to answering only "which bytes are analysable".

# `-h` means a database host only for a database client. For `docker run -h
# prod-1` it is the container hostname, and for most tools it is --help.
DB_CLIENT = re.compile(
    r"^\s*\S*(psql|pg_dump|pg_restore|mysql|mysqldump|mongo|mongosh|mongodump"
    r"|redis-cli|clickhouse-client|sqlcmd|cqlsh)\b")

LOCAL_HOSTS = re.compile(
    r"^(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|.*\.local|.*\.localhost|host\.docker\.internal)$", re.I)

# Bounded: unanchored, `live` matched inside `deliveroo.example.com`.
PROD_HOSTISH = re.compile(r"(^|[.\-_])(prod|production|live)([.\-_]|$)", re.I)

# Defined once, read by Invocation. Four private copies drifted apart once and
# the drift was a production hole.
URI_HOST = re.compile(
    r"(postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|clickhouse)://"
    r"(?:[^\s'\"/@]*@)?([^\s'\"/:?]+)", re.I)

DB_HOST_ENV = r"\b(?:PGHOST|MYSQL_HOST|MONGO_HOST|REDIS_HOST)\s*=\s*([^\s'\"]+)"

# `-h host`, `-h=host`, `--host host` AND the attached short form `-hhost`,
# which psql and mysql both accept. Requiring a separator meant
# `psql -hdb.prod.example.com app` was not a production connection as far as
# this was concerned.
HOST_FLAG = r"(?:^|\s)(?:--host[=\s]+|-h[=\s]*)([^\s'\"=]+)"

# Bounded like PROD_HOSTISH, so `latest.db` does not read as `test`.
DEV_DBISH = re.compile(
    r"(^|[/.\-_])(dev|development|test|testing|tmp|temp|scratch|fixture|sample|local)"
    r"([/.\-_]|$)", re.I)

class Segment(str):
    """The command text with wrappers stripped, plus `raw`, the untouched
    original. Rules that care about an inline `KEY=value` assignment or about
    what was quoted need the original; everything else uses the stripped form.
    """
    def __new__(cls, value, raw, subshell_depth=0):
        s = super().__new__(cls, value)
        s.raw = raw
        s.subshell_depth = subshell_depth
        return s

# NOT `{` or `}`. They only ever meant `{ cmd; }` group commands, but splitting
# on them unconditionally severed `${HOME}` into `rm -rf $` + `HOME`, so
# `rm -rf ${HOME}` was allowed while `rm -rf $HOME` was blocked. A group command
# still resolves without them: `;` splits it, and the git and rm rules strip
# `(){};` off the leading token.
_SPLITTERS = ("||", "&&", ";", "|", "\n", "&", "(", ")")

def _split_unquoted(cmd):
    """Split on shell operators that appear OUTSIDE quotes.

    A naive re.split broke `grep -rnE "DROP TABLE|DELETE FROM" .`, which is a
    search pattern, not two commands.
    """
    out, buf, quote, i, depth = [], [], None, 0, 0
    while i < len(cmd):
        ch = cmd[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            # Backslash escapes inside DOUBLE quotes only. Bash does not honour
            # it inside single quotes, so `echo 'a\' ; rm -rf /` really does end
            # the string and start a new command, and treating the quote as
            # still open swallowed the rm into a segment the prose gate skipped.
            elif ch == "\\" and quote == '"' and i + 1 < len(cmd):
                buf.append(cmd[i + 1]); i += 1
            i += 1
            continue
        # ...and OUTSIDE quotes a backslash escapes the next character, so `\"`
        # is a literal quote, not an opening one. Without this, `echo \" ; rm
        # -rf /` merged the whole line into one prose segment and every rm, SQL,
        # production-database and destructive-tool check was skipped for it.
        if ch == "\\" and i + 1 < len(cmd):
            buf.append(ch); buf.append(cmd[i + 1]); i += 2; continue
        if ch in ("'", '"'):
            quote = ch; buf.append(ch); i += 1; continue
        # A `#` at a word boundary starts a comment. `make build # remember to
        # git push origin main` was being read as two commands.
        #
        # An ESCAPED space is not a word boundary. `echo a\ #note ; rm -rf
        # /var/www` is one word `a #note` followed by a real `;`, so the shell
        # runs the rm while this parser used to discard it as a comment. A
        # guard that sees less than the shell is the worst kind of wrong.
        if ch == "#" and (i == 0 or (cmd[i - 1] in " \t\n;&|("
                                     and not (i >= 2 and cmd[i - 2] == "\\"
                                              and cmd[i - 1] in " \t"))):
            j = cmd.find("\n", i)
            if j == -1:
                break
            i = j
            continue
        matched = next((s for s in _SPLITTERS if cmd.startswith(s, i)), None)
        if matched:
            # Record the operator that FOLLOWS this segment, so callers can
            # tell a piped command from a merely adjacent one.
            out.append(("".join(buf), depth, matched))
            buf = []
            if matched == "(":
                depth += 1
            elif matched == ")":
                depth = max(0, depth - 1)
            i += len(matched)
            continue
        buf.append(ch); i += 1
    out.append(("".join(buf), depth, None))
    return out

# The `q` group captures the quote or backslash, if any. `<<EOF` expands
# `$(...)`, backticks and `$VAR` in the body; `<<'EOF'`, `<<"EOF"` and `<<\EOF`
# do not. Treating them alike let a substitution hide in a body that was then
# blanked as inert.
HEREDOC_OPEN = re.compile(r"<<-?\s*(?P<q>[\\\"'])?(?P<tag>[A-Za-z_][\w]*)[\"']?")

# Anything that executes what it is fed. A heredoc body reaching one of these
# is a program being run, not a file being written.
# The trailing lookahead matters: `\b` alone let `node` inside
# `src/node/index.js` count, so writing a workflow file looked like execution.
# osascript, xargs and eval run what they are handed but take no `-c` payload,
# so they extend the shared set here rather than joining it.
INTERPRETER = re.compile(
    r"(^|[\s(|])(" + _alt(RUNNER_NAMES | {"osascript", "xargs", "eval"}) + r")"
    r"(?=\s|<|$)")

# `bash <<< 'cmd'` and `bash <(echo cmd)` both RUN cmd. The payload is one
# shlex token, so every token-based rule looked straight past it, and the
# heredoc machinery does not fire because neither is a heredoc.
# A fifth copy of the runner list used to live here, and it was missing
# python2, so `python2 -c` carried an unscanned program while `python3 -c` was
# read. Derived from INTERPRETER_NAMES for the same reason as the rest.
INLINE_CODE = re.compile(
    r"^\s*(\S*/)?(" + _alt(INTERPRETER_NAMES) + r")\b[^|;&]*?\s-(c|e)\s+(?P<q>[\"'])"
    r"(?P<code>.*?)(?P=q)", re.S)


def interpreter_heredoc_body(seg):
    """The body of a heredoc handed to an INTERPRETER, or ''.

    `python3 - <<'PY' ... PY` runs its body exactly as `python3 -c '...'` does,
    but INLINE_CODE only matches the `-c`/`-e` shape, so check_inline_code was
    handed '' and never ran. The delete half of that rule was therefore off for
    every heredoc spelling: `shutil.rmtree('/var/www')` blocked as `-c` and ran
    as a heredoc. The credential half looked fine only because the path scanner
    is text-shaped and finds the path wherever it sits.

    That gap contradicted the reassurance written in the accepted-gaps file,
    which told readers a heredoc body is re-entered and still refuses system
    deletes and credential reads. Half of that was true.

    blank_inert_heredocs already decides which bodies are executed and leaves
    exactly those intact, so this asks the same question the same way rather
    than inventing a second answer to it.
    """
    if "<<" not in seg:
        return ""
    lines, out, i = seg.replace("\\\n", " ").split("\n"), [], 0
    while i < len(lines):
        m = HEREDOC_OPEN.search(lines[i])
        if not m or not INTERPRETER.search(lines[i]):
            i += 1
            continue
        tag, j = m.group("tag"), i + 1
        while j < len(lines) and lines[j].strip() != tag:
            j += 1
        out.append("\n".join(lines[i + 1:j]))
        i = j + 1
    return "\n".join(out)


def inline_code(seg):
    """The program inside `python3 -c '...'`, or ''.

    One shlex token holding a whole program. The rules judged the token as a
    filename, which it is not.

    Deliberately NOT the heredoc spelling. segments() splits a heredoc body
    into one segment per line, so a per-segment caller can never see it whole;
    check_command runs interpreter_heredoc_body over the WHOLE command instead.
    """
    m = INLINE_CODE.match(seg)
    return m.group("code") if m else ""


_LEADING_ASSIGN = re.compile(
    r"^\s*[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|\"[^\"]*\"|[^\s]*)\s*")





FED_PAYLOAD = re.compile(r"<<<\s*(?P<herestring>.+)$")


def fed_payloads(seg):
    """Text a here-string feeds to an interpreter: `bash <<< 'cmd'` runs cmd.

    Empty unless the head actually executes what it is handed. NOT process
    substitution: `bash <(echo cmd)` runs the OUTPUT, so the body names the
    producer rather than the program, and scanning it proves nothing.
    """
    if not INTERPRETER.search(seg.split("<")[0]):
        return []
    out = []
    for m in FED_PAYLOAD.finditer(seg):
        body = (m.group("herestring") or "").strip().strip("\"'")
        if body:
            out.append(body)
    return out


# Consumers that read file CONTENTS rather than just names.
# A reader only opens FILES when it is handed filenames as arguments: via
# xargs, via an -I replacement token, or inside a read loop. The same tool on
# bare stdin is just processing the names, which discloses nothing.
CONTENT_READER = re.compile(
    r"^\s*xargs\b"
    r"|^\s*while\s+read\b"
    r"|\{\}"
    r"|^\s*(cat|bat|head|tail|less|more|strings|xxd|od|base64|cp|mv|tee|scp"
    r"|tar|cpio|parallel)\s+(?!-)(?![0-9])\S")

# A find inside a command substitution lands in its own segment, where it
# would keep the metadata-only exemption. If the line also contains anything
# that reads file contents, treat the whole line as a read: the reader may sit
# before the substitution (`cat $(find ...)`) or after it, in a loop body
# (`for f in $(find ...); do cat $f; done`).
SUBST_FINDER = re.compile(r"\$\(\s*(find|ls)\b")

ANY_READER = re.compile(
    r"(^|[\s;&|])(cat|bat|head|tail|less|more|strings|xxd|od|base64"
    r"|cp|mv|tee|scp|grep|awk|sed|perl|python3?)\b")

def _piped_segment_indices(cmd):
    """Indices (into segments()) of segments piping into a CONTENT reader.

    `find . -name X | xargs cat` reads the files, so the finder loses its
    metadata-only exemption. `ls somedir | grep pub` only ever handles names,
    and blocking that is pure nuisance.
    """
    cmd = blank_inert_heredocs(cmd.replace("\\\n", " "))
    parts = [(txt, following) for txt, _, following in _split_unquoted(cmd) if txt.strip()]
    piped = set()
    # `cat $(find . -name X)` reads the files, but `$(`/`)` split the find into
    # its own segment where it would keep the metadata-only exemption.
    if SUBST_FINDER.search(cmd) and ANY_READER.search(cmd):
        return set(range(len(parts)))
    # Walk each pipeline ONCE, right to left. The previous nested walk was
    # quadratic in pipe count: 8000 pipes took 2.7s.
    reader_ahead = False
    for i in range(len(parts) - 1, -1, -1):
        text, following = parts[i]
        if following != "|":
            reader_ahead = CONTENT_READER.match(text.strip()) is not None
            continue
        if reader_ahead or CONTENT_READER.match(text.strip()):
            piped.add(i)
        reader_ahead = reader_ahead or CONTENT_READER.match(text.strip()) is not None
    return piped

def _executed_names(cmd):
    """Every filename the command runs, anywhere in it.

    Computed ONCE for the whole command. The previous shape rejoined all
    remaining lines and ran six regexes over them per heredoc opener, which is
    quadratic: 1100 tiny heredocs (26 KB, well under MAX_ANALYSED) took 6.5
    seconds against a 5 second hook timeout, and a timeout fails open. That is
    a generic disable-the-guard primitive, so the cost has to be linear.

    Ordering is deliberately ignored. Running a file before writing it is not a
    real workflow, and over-blocking that is far cheaper than the timeout was.
    """
    names = set()
    # ...plus `.`/`source`, which run a file without being interpreters, and
    # osascript, which only ever takes a script as an argument.
    runners = (r"(?:^|[\s;&|(])(?:\.|source|" + _RUNNERS
               + r"|osascript)(?:\s+-\S+)*\s+([^\s;&|<>]+)")
    for m in re.finditer(runners, cmd):
        names.add(m.group(1).strip("'\""))
    # `chmod +x X` is preparation to run it, and `./X` is running it.
    for m in re.finditer(r"(?:^|[\s;&|(])chmod\s+\+x\s+([^\s;&|<>]+)", cmd):
        names.add(m.group(1).strip("'\""))
    for m in re.finditer(r"(?:^|[\s;&|(])\./([^\s;&|<>]+)", cmd):
        names.add("./" + m.group(1).strip("'\""))
    # Redirection and pipes run a script just as well as naming it as an
    # argument: `bash < x.sh`, `cat x.sh | bash`, `eval "$(cat x.sh)"`.
    for m in re.finditer(r"(?:^|[\s;&|(])(?:\.|source|" + _RUNNERS
                         + r")\b[^\n;&|]*<\s*([^\s;&|<>]+)", cmd):
        names.add(m.group(1).strip("'\""))
    if re.search(r"\|\s*\S*(" + _RUNNERS + r")\b", cmd) \
            or re.search(r"\beval\b", cmd):
        # The file is named upstream of the pipe, or inside the eval.
        for m in re.finditer(r"(?:^|[\s;&|(])(?:cat|bat|head|tail)\s+([^\s;&|<>]+)", cmd):
            names.add(m.group(1).strip("'\""))
    out = set()
    for n in names:
        if not n:
            continue
        out.add(n)
        out.add(n.lstrip("./"))
        out.add(os.path.basename(n))
    return {n for n in out if n}

def _written_then_run(opener, executed):
    """Is this heredoc's redirect target among the names the command runs?

    Writing a script is not running it, which is why bodies are blanked at all.
    But `cat > /tmp/x.sh <<EOF ... EOF` followed by `bash /tmp/x.sh` in the SAME
    tool call is running it, and blanking the body hid the whole payload.
    """
    if not executed:
        return False
    # Every way the whitelisted openers name their destination: a redirect,
    # `tee FILE`, or `dd of=FILE`. Knowing only `>` meant `tee /tmp/x.sh <<EOF`
    # wrote the payload with the body blanked.
    m = (re.search(r">>?\s*([^\s|&;<>]+)", opener)
         or re.search(r"\btee\b(?:\s+-\S+)*\s+([^\s|&;<>]+)", opener)
         or re.search(r"\bdd\b[^\n]*\bof=([^\s|&;<>]+)", opener))
    if not m:
        return False
    target = m.group(1).strip("'\"")
    if not target:
        return False
    # Compare on the basename too: `cat > ./x.sh` then `bash x.sh` is one file.
    return bool({target, target.lstrip("./"), os.path.basename(target)} & executed)

# A commit message or PR body is prose, and these consumers store stdin
# without ever executing it. `git commit -m "..."` was already exempt, because
# check_git strips quoted runs before matching, so ONLY the heredoc spellings
# were refused: exactly the spelling any message longer than one line uses. The
# effect was that an agent could not describe what the guard blocks in a commit
# message. The unquoted-delimiter and pipe checks below still apply, so
# `git commit -F - <<EOF` carrying a live $(...) is still scanned.
MESSAGE_FILE_OPENER = re.compile(
    r"(^|\s)git\s+(commit|tag|notes)\b[^|]*?\s(-F|--file)(=|\s*)-(?=\s|$)"
    r"|(^|\s)gh\b[^|]*?\s(--body-file|--notes-file)(=|\s*)-(?=\s|$)")


def blank_inert_heredocs(cmd):
    """Blank heredoc bodies that are file CONTENT rather than executed input.

    Writing a script that contains `git commit` is not running `git commit`,
    so `cat > deploy.sh <<'EOF' ... EOF` must not trip the git rules. A body
    fed to a SQL client IS executed, so those are left intact.
    """
    if "<<" not in cmd:
        return cmd
    cmd = cmd.replace("\\\n", " ")   # a continued opener is still one line
    executed = _executed_names(cmd)     # ONCE, not once per opener
    lines, i = cmd.split("\n"), 0
    while i < len(lines):
        m = HEREDOC_OPEN.search(lines[i])
        if m:
            opener = lines[i]
            tag = m.group("tag")
            # Find the terminator FIRST. An unterminated heredoc used to blank
            # every remaining line, which hid whatever followed.
            j = i + 1
            while j < len(lines) and lines[j].strip() != tag:
                j += 1
            terminated = j < len(lines)
            # Whitelist, not blacklist: a body is inert only when it is written
            # into a file and nothing executes it. `bash <<EOF`, `cat <<EOF |
            # bash`, and `python3 <<PY` all run their bodies.
            # An UNQUOTED delimiter means bash expands the body before the
            # file is written, so a substitution in there executes now.
            expands = m.group("q") is None
            # `$(` may have been split by a backslash-newline, which the join
            # at the top of this function has already turned into `$ (`. Look
            # for the joined spelling too, or the detector goes blind to it.
            has_subst = expands and any(
                ("$(" in lines[k] or "$ (" in lines[k] or "`" in lines[k])
                for k in range(i + 1, j))
            inert = (terminated
                     and not has_subst
                     and not INTERPRETER.search(opener)
                     and not is_sql_context(opener)
                     and "|" not in opener
                     and (re.search(r"(^|\s)(cat|tee|dd)\b|>\s*[^\s|&]+", opener)
                          or MESSAGE_FILE_OPENER.search(opener)))
            # ...and only if nothing LATER in this same command runs the file
            # it was written to. `cat > /tmp/x.sh <<EOF ... EOF; bash /tmp/x.sh`
            # is one tool call: the body is right there and it does execute.
            if inert and _written_then_run(opener, executed):
                inert = False
            if inert:
                for k in range(i + 1, j):
                    lines[k] = ""
            i = j + 1
            continue
        i += 1
    return "\n".join(lines)

# Does this inline program hand a string to a shell or to another process?
# `python3 -c "print('kubectl delete ns x')"` names a command; the same program
# with os.system RUNS it. The quoted literal is data in the first and a payload
# in the second, so the rules may only treat it as prose when none of these
# appear.
PROGRAM_EXECUTES = re.compile(
    r"\b(os\.(system|popen|exec\w*|spawn\w*)"
    r"|subprocess\.\w+|commands\.getoutput"
    r"|child_process|execSync|spawnSync|\bexecFile\b"
    r"|Kernel#?system|IO\.popen|%x\{"
    r"|shell_exec|passthru|proc_open"
    r"|\bsystem\s*\(|\bexec\s*\(|\beval\s*\()", re.I)


# Characters that can start a new command inside an unwrapped payload.
SPLITTER_HINT = re.compile(r"[;&|\n]")


# SHELL_NAMES and INTERPRETER_NAMES are defined at the top of this module,
# next to RUNNER_NAMES, so the membership cannot drift from the alternation
# built out of it.


# How far in to look for the interpreter name. It was 4, with no comment, and
# one extra flag on a wrapper was enough to walk past it: `timeout 5 bash -c
# 'rm -rf /'` blocked and `timeout -s 9 5 bash -c 'rm -rf /'` did not, because
# `-s 9` pushed `bash` to index 4. `timeout -k 10 -s TERM 30 cmd` is longer
# still. Widening this is cheap and safe: finding the name proves nothing on
# its own, the flag walk below still has to find a real `-c`/`-e`, and the
# wrappers themselves are stripped before this in the common case.
_RUNNER_SCAN = 8


def _dash_c_payload(toks):
    r"""The command an interpreter was handed via -c or -e, and whether it is a shell.

    Returns (payload, is_shell), or (None, False) when this is not that shape.

    Everything here is a lesson from a bypass:

      The name is matched on the BASENAME, exactly. A prefix match let `ssh`
      count as a shell, and `ssh -c <cipher> host '<cmd>'` then had its cipher
      argument taken as the command while the real one was discarded.

      A long option is never the flag. `--norc` ends in `c`, and a pattern of
      `-[\w-]*c` matched it, so `bash --norc -c '<cmd>'` yielded the literal
      string `-c` as the whole command. That was a total, silent bypass.

      Options are SKIPPED rather than assumed absent. Requiring the flag at
      position 1 meant `bash -euo pipefail -c '<cmd>'`, the commonest preamble
      in any CI script, was never unwrapped at all.
    """
    start = None
    for i, tok in enumerate(toks[:_RUNNER_SCAN]):
        if os.path.basename(tok.strip("'\"")) in SHELL_NAMES | INTERPRETER_NAMES:
            start = i
            break
    if start is None:
        return None, False
    name = os.path.basename(toks[start].strip("'\""))
    is_shell = name in SHELL_NAMES
    # `-e` means "here is the program" to perl and node, and "errexit" to a
    # shell. Accepting it for both made `sh -e -c '<cmd>'` take the literal
    # `-c` as its payload, which is the same class of bug as `--norc`.
    flags = ("c",) if is_shell else ("c", "e")
    for i in range(start + 1, len(toks)):
        tok = toks[i]
        if tok == "--":
            return None, False
        if tok.startswith("--"):
            continue                      # a long option is never -c or -e
        if tok.startswith("-") and len(tok) > 1 and tok[1:].isalpha() \
                and any(f in tok[1:] for f in flags):
            # `-c`, or a bundled short group CONTAINING it. Requiring it last
            # meant `bash -cx '<cmd>'` was not unwrapped: a real shell takes
            # the payload from the next argument wherever `c` sits in the
            # group, and `-cx` is a spelling people use to trace a script.
            # `--norc` cannot reach here; long options are skipped above.
            return (toks[i + 1], is_shell) if i + 1 < len(toks) else (None, False)
        # Any other option, or an option value such as `pipefail` after `-o`.
        # Keep scanning: the flag may still be ahead.
    return None, False


def segments(cmd, _depth=0):
    """Split a command line into independently-checkable segments.

    Backslash-newline is joined first: the shell treats it as one command, and
    splitting on it let `git push \\<newline> --force` through.

    `_depth` bounds the re-split of an unwrapped `-c` payload. See below.
    """
    cmd = cmd.replace("\\\n", " ")
    parts = _split_unquoted(cmd)
    out = []
    for p, depth, _following in parts:
        raw = p.strip()
        if not raw:
            continue
        # A leading `KEY=value` is removed from the STRING first, quotes and
        # all. Stripping it by whitespace token instead cut
        # `NOTE="never run git push --force"` after `NOTE="never`, leaving
        # `run git push --force"` to be judged as a command. Whether that
        # reads as a false positive or as a way to hide half a command from a
        # rule depends only on where the quote falls.
        # `raw` itself is never touched: the production-database and GIT_DIR
        # rules read the assignment out of it.
        head = raw
        while True:
            m = _LEADING_ASSIGN.match(head)
            if not m:
                break
            head = head[m.end():]
        if not head.strip():
            # The whole segment is assignments. `NOTE="never run git push
            # --force"` runs nothing, and judging it as a command refused a
            # note to yourself. The raw text is kept so the db and GIT_DIR
            # rules can still read the value.
            out.append(Segment(raw, "", depth))
            continue
        # An inline `KEY=value` prefix is stripped so the real command is seen,
        # but the ORIGINAL text is kept as `raw` because rules like the
        # production-database check need to inspect that assignment.
        toks = strip_wrapper_prefix(head).split()
        if not toks:
            out.append(Segment(raw, raw, depth))
            continue
        s = " ".join(toks)
        # Unwrap a whole command hidden in one quoted argument, so
        # `eval 'git commit -m x'` and `bash -c "rm -rf /"` are seen.
        #
        # Tokenised, not regexed. shlex.join escapes a nested single quote as
        # '"'"', and a greedy ['"](.+)['"] eats straight through that soup and
        # yields text that is neither the wrapper nor the payload. That is not
        # hypothetical: it is exactly what a host produces when it hands over
        # an argv list containing an inner quoted command.
        unwrapped_shell = False
        for _ in range(3):
            payload, is_shell = _dash_c_payload(tokens(s))
            if payload is not None:
                s = payload.strip()
                # A SHELL payload is a command line and gets re-split below. An
                # interpreter payload is a PROGRAM, where `;` separates
                # statements rather than commands, so splitting it would
                # destroy what check_inline_code needs to read.
                unwrapped_shell = is_shell
                continue
            m = re.fullmatch(r"""['"](.+)['"]""", s.strip())
            if m:
                s = m.group(1).strip()
                unwrapped_shell = True
                continue
            break
        # What comes out of that unwrap is a command LINE, not one command, and
        # emitting it as a single segment was a live fail-open:
        # `bash -c 'echo hi; rm -rf /'` produced one segment whose head is
        # `echo`, MESSAGE_BEARING called the whole thing prose, and every rule
        # after that was skipped. The single-command spellings blocked, which
        # is why six existing `-c` cases never caught it: not one of them put
        # two commands in the payload.
        #
        # Re-split through segments() itself rather than inline, so the payload
        # gets the same wrapper and KEY=value stripping as any other line.
        # Depth-bounded: a payload can nest another `-c`, and the recursion has
        # to terminate whatever an adversary writes.
        if unwrapped_shell and _depth < 2 and SPLITTER_HINT.search(s):
            for sub in segments(s, _depth + 1):
                out.append(Segment(str(sub), getattr(sub, "raw", str(sub)), depth))
            continue
        # Once unwrapped, the PAYLOAD is the command, so it is also the raw
        # text. Keeping the wrapper as `raw` meant the prose path ran
        # strip_quoted over `bash -lc '<payload>'` and deleted the entire
        # payload, so `bash -lc 'grep KEY .env'` read as an empty command.
        # Any KEY=value prefix a rule needs is inside the payload anyway.
        # SHELL unwraps only. For a python or ruby payload the wrapper has to
        # survive as `raw`, because check_inline_code matches on the whole
        # `python3 -c '...'` invocation and cannot recognise a bare program.
        out.append(Segment(s, s if unwrapped_shell else raw, depth))
    return out

def strip_quoted(s):
    """Remove quoted runs, so a commit MESSAGE that mentions a destructive
    command is not mistaken for the command."""
    return re.sub(r"'[^']*'|\"[^\"]*\"", " ", s)

def normalize_path(tok):
    """Strip quotes, expand ~ and $HOME, resolve .., drop trailing slashes.

    Also strips a git object prefix: in `git show HEAD:.env` the real path is
    everything after the colon, and without this it matched nothing.
    """
    t = tok.strip().strip("'\"")
    # `${HOME:?}` and `${HOME:-/tmp}` carry a colon that is parameter-expansion
    # syntax, not a git object prefix. Splitting on it left `?}` and lost HOME.
    # For HOME itself the substitution below now handles the colon form too, so
    # this is belt and braces there; it is load-bearing for any OTHER variable,
    # where the partition would otherwise mangle the path.
    if t.startswith("${"):
        t = re.sub(r"^\$\{(\w+)(:[^}]*)?\}", r"${\1}", t)
    elif ":" in t and "://" not in t:
        head, _, tail = t.partition(":")
        # `git show HEAD:.env` puts the real path after the colon. But
        # `docker run -v ~/.aws:/x` puts it BEFORE, and blindly keeping the
        # tail threw the secret half away. A head that is itself a path is not
        # a git object name.
        if head[:1] in ("/", "~", ".", "$"):
            t = head
        elif tail and not head.startswith("-"):
            t = tail
    # `${HOME:?}`, `${HOME:-/tmp}` and friends are still HOME. Matching only
    # the bare form let `rm -rf ${HOME:?}` through.
    t = re.sub(r"^\$\{HOME(:[^}]*)?\}|^\$HOME\b", os.path.expanduser("~"), t)
    t = re.sub(r"^~", os.path.expanduser("~"), t)
    # `/./` is a no-op component that no rule should ever see, and `..` needs
    # collapsing whether or not the path is absolute. Leaving either in place
    # meant `rm -rf ~/./*` and `cat ~/.aws/./credentials` were unrecognisable
    # while the same paths without the `/./` were caught.
    if ".." in t or "/./" in t:
        keep_trailing = t.endswith("/")
        t = os.path.normpath(t)
        if keep_trailing and not t.endswith("/"):
            t += "/"
    if len(t) > 1:
        t = t.rstrip("/")
    return t

def tokens(seg):
    try:
        return shlex.split(seg)
    except ValueError:
        return seg.split()

class Invocation:
    """A segment parsed once, for rules to query instead of re-parsing.

    raw       as written, with KEY=value prefixes. What the command POINTS AT:
              PGHOST=prod and DOCKER_HOST= live here and nowhere else.
    stripped  wrappers and those prefixes removed. What the command IS, so
              `sudo git push` is found by basename.

    Getting raw/stripped backwards is the shape of most bypasses here. Rules
    must not re-derive any of this; add a property instead.
    """

    __slots__ = ("raw", "stripped", "_memo")

    def __init__(self, raw, stripped=None):
        self.raw = str(raw)
        self.stripped = str(stripped) if stripped is not None else self.raw
        self._memo = {}

    def __repr__(self):
        return f"Invocation({self.raw[:60]!r})"

    def _c(self, key, fn):
        if key not in self._memo:
            self._memo[key] = fn()
        return self._memo[key]

    @property
    def unwrapped(self):
        """`raw` with only the wrapper prefix removed.

        `stripped` cannot be used for this: it may have been replaced by a
        `-c` PAYLOAD, which is a program rather than an invocation, so the
        inline-program rule would no longer see the interpreter it needs to
        match. `raw` keeps the invocation but also keeps the wrapper, and the
        rule is anchored on the head, so `sudo node -e ...` slipped past.
        """
        return self._c("unwrapped", lambda: strip_wrapper_prefix(self.raw))

    @property
    def toks(self):
        return self._c("toks", lambda: tokens(self.stripped))

    @property
    def is_db_client(self):
        return self._c("dbc", lambda: bool(DB_CLIENT.match(self.stripped)))

    @property
    def is_sqlite(self):
        return self._c("sqlite", lambda: bool(
            re.match(r"^\s*\S*sqlite3?\b", self.stripped)))

    @property
    def is_docker_exec(self):
        """A container on THIS machine. -H/--context/DOCKER_HOST retarget the
        daemon, and the flag is capital -H so the host scan never sees it."""
        return self._c("dex", lambda: bool(
            re.search(r"\bdocker\b[^|;&]*\bexec\b", self.raw, re.I)
            and not re.search(
                r"(^|\s)(-H|--host|--context)[=\s]|\bDOCKER_HOST\s*=", self.raw)))

    @property
    def all_hosts(self):
        """Every host this could be talking to. UNGATED: finding more is the
        safe direction for is_local_db, where one unvouched host defeats it."""
        return self._c("allh", lambda: (
            re.findall(HOST_FLAG, self.raw)
            + [m.group(2) for m in URI_HOST.finditer(self.raw)]
            + re.findall(DB_HOST_ENV, self.raw, re.I)))

    @property
    def db_hosts(self):
        """Hosts to JUDGE as production. GATED on is_db_client, because this
        one drives a block: outside a client, -h is --help."""
        def _v():
            out = ([m.group(2) for m in URI_HOST.finditer(self.raw)]
                   + re.findall(DB_HOST_ENV, self.raw, re.I))
            if self.is_db_client:
                out += re.findall(HOST_FLAG, self.raw)
                out += re.findall(r"\bhost\s*=\s*([^\s'\";]+)", self.raw, re.I)
            return out
        return self._c("dbh", _v)

    @property
    def prod_host(self):
        return self._c("prodh", lambda: next(
            (h for h in self.db_hosts
             if not LOCAL_HOSTS.match(h) and PROD_HOSTISH.search(h)), None))

    @property
    def sqlite_target(self):
        def _v():
            if not self.is_sqlite:
                return ""
            args = [a for a in self.toks[1:] if not a.startswith("-")]
            return args[0] if args else ""
        return self._c("sqt", _v)

    @property
    def is_local_db(self):
        """PROVABLY a database on this machine. Default False: no host means
        PGHOST decides, and the guard cannot see PGHOST."""
        def _v():
            if self.all_hosts:
                # ALL, not any: a line naming both a local and a remote host
                # is not local.
                return all(LOCAL_HOSTS.match(h) for h in self.all_hosts)
            if self.is_docker_exec:
                return True
            # sqlite has no host; the database IS the file. A deployed app.db
            # is real, so only an explicit dev/test name counts.
            t = self.sqlite_target
            return bool(self.is_sqlite and (
                t == ":memory:"
                or (DEV_DBISH.search(t) and not PROD_HOSTISH.search(t))))
        return self._c("local", _v)

# SQL rules only apply where SQL is actually being run. Without this,
# `npm test -- -t 'delete from cart'` and `jest --testNamePattern='...update
# users set...'` were blocked: the words appear inside a quoted test-name filter.
SQL_CONTEXT = re.compile(
    r"\b(psql|pgcli|mysql|mycli|mysqldump|mariadb|sqlite3|litecli|duckdb|usql"
    r"|sqlcmd|snowsql|bq|wrangler|turso|trino|athena|presto|mongosh|mongo"
    r"|clickhouse-client|cockroach|redis-cli"
    r"|prisma|supabase|alembic|flyway|liquibase|knex|sequelize|rails|dbmate|atlas)\b"
    # NOTE: a bare `.sql` filename is NOT context. `cat schema.sql | grep ...`
    # reads the file, it does not execute it; a real client name above covers
    # `psql -f schema.sql`.
    r"|<<\s*'?EOSQL"
    , re.I)

# A statement flag carrying a SQL verb, but ONLY alongside something that looks
# like a database client. On its own it fired for `grep -e 'DELETE FROM x'`.
SQL_STATEMENT_FLAG = re.compile(
    r"(-c|-e|-Q|--command|--eval|--sql|--execute)[=\s]+[\"']?\s*"
    r"(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNC|ALTER|CREATE)\b", re.I)

SQL_CLIENTISH = re.compile(r"\b(psql|mysql|mariadb|mongosh|mongo|redis-cli|clickhouse\w*)\b", re.I)

# ---- which database clients, for which question ---------------------------
#
# These look like drifted copies of one list. They are not. Four questions get
# four answers, and merging them would be wrong in both directions:
#
#   DB_CLIENT       does `-h` mean a database HOST here? Needs tools that
#                   actually take -h, which is why the migration frameworks are
#                   absent: `prisma -h` is --help.
#   SQL_CONTEXT     is this line ABOUT a database at all? Deliberately the
#                   widest, so a migration tool counts.
#   SQL_CLIENTISH   does a `-c`/`-e` flag on this line carry a SQL STATEMENT?
#                   Narrow on purpose: `grep -e` is a pattern.
#   FILE_FED_CLIENT can this client be handed a script to EXECUTE, by `-f` or
#                   on stdin? That is the one below, and it was two lists that
#                   disagreed with each other.
#
# `mongosh?` matches "mongos" and "mongosh" but NOT "mongo", so the legacy
# shell slipped both file-fed scans. And stdin listed four clients when
# mongosh, redis-cli and clickhouse all read stdin too.
FILE_FED_CLIENT = r"psql|mysql|mariadb|mongosh|mongo|sqlite3?|clickhouse\w*|redis-cli"

# A tool whose `-e` is a pattern or a script, never a SQL statement.
#
# INCLUDES sed and awk, and guard_secrets.PATTERN_FIRST_OPERAND deliberately
# does not. Different question: `sed -e 's/DELETE FROM x/y/'` is not SQL, so it
# belongs here, but `sed -n 1p <secret>` still READS the secret, so sed must
# not be exempt there. The two lists used to share the name SEARCHER, which
# made the difference look like drift and invited a merge that would have
# broken one of them.
PATTERN_TAKING_TOOL = re.compile(
    r"^\s*\S*(grep|rg|ag|ack|fgrep|egrep|sed|awk|rga)\b")

class SqlFragment(str):
    """One statement pulled out of a multi-statement command line.

    Marked, because the client name that established SQL context lives in the
    enclosing segment, not in the fragment.
    """

# `> path` and `>> path`, outside quotes. Not `2>&1`, not a here-doc marker,
# and not `>` inside a quoted argument.
_REDIRECT = re.compile(r"(?<![<>&\d])>>?\s*(?![&|(])([^\s;&|<>()\"']+)")


def redirect_targets(seg):
    """Files this segment writes with a shell redirect.

    The file guard already knows which paths must not be written. It was only
    ever asked about the Write and Edit tools, so the same path reached through
    `printf ... > .git/hooks/pre-commit` was never checked at all. One parser,
    one rule set, two ways in.
    """
    if ">" not in seg:
        return []
    return [m.group(1) for m in _REDIRECT.finditer(strip_quoted(seg))
            if m.group(1)]


_SQL_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def strip_sql_comments(s):
    """SQL with the parts the database ignores removed.

    A comment is not a clause. `DELETE FROM users -- WHERE id=1` deletes every
    row, and so does `DELETE FROM users /*WHERE id=1*/`, but both satisfied a
    plain `\\bWHERE\\b` over the raw text. `/**/` also splits keywords:
    `DELETE/**/FROM users` is a DELETE FROM to the database and was not one to
    the regex.

    `--` is only a comment INSIDE the quoted statement. Outside it, `--` starts
    a command-line flag, and stripping to end-of-line there deleted the SQL
    itself: `wrangler d1 execute mydb --command "DELETE FROM sessions"` stopped
    being a DELETE at all, turning a comment fix into a leak. The quote
    boundary is what tells the two apart.

    A block comment becomes a SPACE rather than nothing, so removing it cannot
    weld two words into one and invent a keyword that was never there.
    """
    s = _SQL_BLOCK_COMMENT.sub(" ", s)
    out, i, quote = [], 0, None
    while i < len(s):
        ch = s[i]
        if quote:
            if ch == quote:
                quote = None
                out.append(ch)
            elif ch == "-" and s[i + 1:i + 2] == "-":
                # To end of statement or line, whichever comes first: the
                # closing quote still has to survive for the callers that
                # anchor on it.
                nl = s.find("\n", i)
                end = s.find(quote, i)
                stop = min(x for x in (nl, end, len(s)) if x != -1)
                i = stop
                continue
            else:
                out.append(ch)
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
        out.append(ch)
        i += 1
    return "".join(out)


def is_sql_context(s):
    if isinstance(s, SqlFragment):
        return True
    if PATTERN_TAKING_TOOL.match(s):
        return False
    return bool(SQL_CONTEXT.search(s)
                or (SQL_STATEMENT_FLAG.search(s) and SQL_CLIENTISH.search(s)))

GLOBBED = re.compile(r"[*?\[{]")

def _is_dot_walk(tok):
    """`.`, `..`, `../..`, `../*`: the current tree or an ancestor of it.

    The PWD variable and its command-substitution spellings mean the same
    thing, and were allowed while the bare dot blocked.
    """
    tok = tok.strip("'\"")
    if re.fullmatch(r"\$\{?PWD\}?|\$\(\s*pwd\s*\)|`\s*pwd\s*`", tok):
        return True
    return bool(re.fullmatch(r"\.{1,2}(/\.{1,2})*/?\*?", tok))

# Total brace members expanded across ONE check_command call. Per-token limits
# are not enough: the cost is members x tokens x segments, and a payload of
# nothing but brace tokens blew the hook timeout with no special repo state.
MAX_BRACE_WORK = 4000

_BRACE_BUDGET = [MAX_BRACE_WORK]

def _brace_fragments(tok, cap=256):
    """Every path a partially-expanded brace token could still stand for.

    Expansion gives up past its limits, and the leftover text cannot be judged
    as one string: concatenating `{a,b}` into `ab` produces a path that is
    neither. Pair the literal prefix and suffix with each member instead, which
    over-blocks (a member is judged even if a sibling brace would have changed
    it) rather than under-blocking.
    """
    out = []
    # THREE INDEPENDENT GUARDS stop the divergence below, and each one alone is
    # sufficient: the well-formed-pair test here, the brace strip on the way
    # out, and the strictly-smaller filter at the call site in
    # is_secret_candidate. Verified by mutation: reverting any one or any two
    # still terminates; reverting all three brings the hang back. That means no
    # single test can pin any of them, so do not "simplify" one away. The
    # failure mode is not a wrong verdict, it is a hung hook, and a hung hook
    # fails open at the 5 second timeout.
    #
    # A well-formed pair only. `awk '{s+=$1}END{print s}'` yields the candidate
    # `1}END{print`, where `}` precedes `{`; taking head before the first `{`
    # and tail after the last `}` then kept BOTH braces, so every fragment came
    # back still braced and LONGER than its input, and the caller recursed on
    # them without end.
    lo, hi = tok.find("{"), tok.rfind("}")
    if lo == -1 or hi == -1 or hi < lo:
        return []
    head, tail = tok[:lo], tok[hi + 1:]
    for frag in re.split(r"[{},]+", tok):
        if not frag:
            # An EMPTY member means the prefix alone: `~/{,.config}` includes
            # `~/`, which is what makes it an rm on the home directory.
            out.append(head + tail)
            continue
        out.append(frag)
        out.append(head + frag + tail)
        if len(out) >= cap:
            break
    # ...and the empty-member case again, since re.split drops a trailing one.
    if re.search(r"[{,]\s*[},]", tok) or tok.rstrip().endswith(",}"):
        out.append(head + tail)
    # NOTHING braced comes out of here. head and tail are taken from outside
    # the outermost pair, so a nested brace could still ride along; strip any
    # survivor rather than hand the caller something it will recurse on.
    return [x for x in ((y.replace("{", "").replace("}", "")) for y in out) if x][:cap]

def brace_expand(tok, limit=64):
    """Expand `a{b,c}d` the way the shell does, into ['abd', 'acd'].

    shlex keeps a brace list as ONE token, so every rule that looks at whole
    paths saw `~/.aws/{credentials,config}` as a literal matching nothing.
    Handles one level of nesting by expanding repeatedly, and gives up rather
    than growing without bound.
    """
    tok = tok.strip("'\"")
    if _BRACE_BUDGET[0] <= 0:
        return [tok]        # budget spent; callers fall back to the fragments
    out = [tok]
    truncated = False
    for _ in range(4):
        nxt = []
        grew = False
        for item in out:
            m = re.search(r"\{([^{}]*)\}", item)
            if not m or len(nxt) >= limit:
                if m:
                    truncated = True
                nxt.append(item)
                continue
            grew = True
            head, tail = item[:m.start()], item[m.end():]
            # `{,.config}` has an empty member, which means the prefix alone.
            for part in m.group(1).split(","):
                nxt.append(head + part.strip() + tail)
                if len(nxt) >= limit:
                    truncated = True
                    break
        out = nxt
        _BRACE_BUDGET[0] -= len(out)
        if not grew:
            break
        if _BRACE_BUDGET[0] <= 0:
            truncated = True
            break
        if truncated:
            break
    res = [x for x in out if x]
    # Hand the UNEXPANDED token back when members were dropped, so the caller
    # can see expansion was incomplete and judge the fragments too. Truncating
    # silently at the limit meant a dangerous member in position 71 of a
    # 70-member list was never produced and never judged, and an empty member
    # there stands for the bare prefix.
    if truncated and "{" in tok:
        res.append(tok)
    return res

def _shell_fed_indices(cmd):
    """Segments whose output feeds an interpreter: the "message" IS the command.

    ONE right-to-left pass. Scanning forward per piped segment was O(N^2) and
    8000 pipes hung the hook, which fails open.
    """
    parts = [(txt, following) for txt, _d, following in _split_unquoted(
        blank_inert_heredocs(cmd.replace("\\\n", " "))) if txt.strip()]
    out = set()
    fed_or_shell = False
    for i in range(len(parts) - 1, -1, -1):
        txt, following = parts[i]
        if following == "|" and fed_or_shell:
            out.add(i)
        fed_or_shell = bool(_SHELL_HEAD.match(txt)) or i in out
    return out

def _cap_segments(segs):
    """Bound the segment list without opening a truncation bypass.

    Dedup, not truncate: 500 copies of `true` then a destructive command slipped
    past a tail cap. Keep head AND tail: head-only let 1600 distinct prefixes
    reopen it.
    """
    seen, deduped = set(), []
    for s in segs:
        k = " ".join(str(s).split())[:200]
        if k in seen:
            continue
        seen.add(k)
        deduped.append(s)
    keep = MAX_SEGMENTS * 4
    if len(deduped) > keep:
        deduped = deduped[:keep - MAX_SEGMENTS] + deduped[-MAX_SEGMENTS:]
    return deduped

def split_oversize(cmd):
    """Split a command too long to analyse into (analysable, discarded middle).

    Mechanical, no policy. Analysing a 270KB write in full took 163s, so only
    a head and a tail are kept. Head AND tail, because padding either side
    alone was a working bypass. The caller decides what the discarded middle
    means: see guard_rules._oversize_verdict.

    Returns (cmd, "") when the whole command fits.
    """
    if len(cmd) <= MAX_ANALYSED:
        return cmd, ""
    return (cmd[:MAX_ANALYSED] + "\n" + cmd[-TAIL_ANALYSED:],
            cmd[MAX_ANALYSED:-TAIL_ANALYSED])
