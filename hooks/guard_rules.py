#!/usr/bin/env python3
"""Agent-neutral guardrail rules.

The single source of truth for what is blocked. Adapters (guard-bash.py,
guard-files.py, guard-codex.py) translate their host agent's hook payload into
these calls. Add a rule here once and every agent gets it.

Every check returns None to allow, or a (reason, fix) tuple to block.
Nothing here writes to stdout/stderr or exits: that is the adapter's job.

WHAT THIS IS NOT: a security boundary. It fails open by design, and a
determined agent can defeat it. It is a safety net for the obvious mistakes.
Run tests.py after any change to this file, with and without --no-perf.

The invariants two adversarial passes established are documented where they
are implemented, not summarised here: a summary of seven other modules goes
stale silently, and a stale note about a fail-open is worse than none.
"""
import os
import re
import sys
import shlex


# Facade. Adapters and both suites import guard_rules and nothing else, so
# every name stays reachable from here. Star imports on purpose: a facade is
# the one place they are not a smell, and hand-keeping the hundred-odd
# re-exports means every new rule needs a second edit or it is silently
# missing.
from guard_parse import *          # noqa: F401,F403
from guard_git import *          # noqa: F401,F403
from guard_secrets import *          # noqa: F401,F403
from guard_db import *          # noqa: F401,F403
from guard_tools import *          # noqa: F401,F403
# The file guard, re-exported so guard-files.py and PATH_CASES are
# unchanged by it having moved out of this file.
from guard_paths import *          # noqa: F401,F403
from guard_paths import check_control_path, check_guard_mutation, check_path  # noqa: F401

# Private names the orchestrator itself calls; star imports skip these.
from guard_parse import (  # noqa: F401
    _BRACE_BUDGET,
    interpreter_heredoc_body,
    _cap_segments,
    _piped_segment_indices,
    _shell_fed_indices,
    split_oversize,
)

# By module, not through the star imports above: each rule module exports a
# MIDDLE_SIGNALS of its own, so a star import would silently keep whichever one
# came last. That is how two SEARCHER definitions once disagreed, resolved by
# line order rather than by anyone deciding.
import guard_db          # noqa: E402
import guard_git          # noqa: E402
import guard_secrets          # noqa: E402
import guard_tools          # noqa: E402

# The union, and the only MIDDLE_SIGNALS the facade exports. A rule module that
# gains a rule and declares its signal is covered here with no edit to this
# file, which is the property the parser's hand-copied version could not hold.
# DISCOVERED, not hand-listed. The literal `+` chain that used to be here had
# five of the six rule modules in it, and the missing one was guard_paths: the
# module protecting the guard's own files. That is the failure mode a hand-kept
# union has, and writing "keep this in sync" above it is what the four
# spellings of RUNNER_NAMES already proved does not work. A module that gains
# MIDDLE_SIGNALS is now covered with no edit to this file.
_SIGNAL_SOURCES = tuple(
    m for name, m in sorted(sys.modules.items())
    if name.startswith("guard_") and name != __name__
    and hasattr(m, "MIDDLE_SIGNALS")
    and isinstance(getattr(m, "MIDDLE_SIGNALS"), tuple))
MIDDLE_SIGNALS = re.compile(
    "|".join(sum((tuple(m.MIDDLE_SIGNALS) for m in _SIGNAL_SOURCES), ())), re.I)


def _oversize_verdict(cmd):
    """Trim a command that is really file content, or refuse it.

    The parser decides which bytes are analysable; this decides what the bytes
    it threw away mean. Splitting those two is the whole point: the list of
    things worth finding in the middle is policy, and when it lived in the
    parser it drifted out of step with the rules it was shadowing.
    """
    analysable, middle = split_oversize(cmd)
    if middle and MIDDLE_SIGNALS.search(middle):
        return cmd, ("a destructive command buried in the middle of an oversized "
                     "command line, which is too long to analyse in full.",
                     "run the destructive part as its own command, so it can be "
                     "judged on its own")
    return analysable, None
from guard_git import (  # noqa: F401
    _note_checkout,
    _note_git_init,
)
import guard_repo          # noqa: E402
from guard_secrets import (  # noqa: F401
    _is_secret_path,
    _substitution_bodies,
)


MESSAGE_BEARING = re.compile(
    r"^\s*(git\s+(commit|tag|notes)|gh\s+(pr|issue|release)\s+(create|edit|comment)"
    r"|git\s+(log|show|grep|blame)"
    r"|echo|printf|say|grep|rg|ag|ack|fgrep|egrep)\b"
)


# One level of re-entry only, for scanning the inside of a command
# substitution. Deeper nesting is already flattened by _substitution_bodies,
# and unbounded recursion here would be a fresh way to blow the hook timeout.
depth_guard = [0]

CD_PREFIX = re.compile(
    r"^(?:cd|pushd)(?:\s+(?:-[LP]|--))*\s+(?P<dir>'[^']+'|\"[^\"]+\"|[^\s>&]+)"
    r"(?:\s+\d?>[>&]?\s*\S+)*\s*$")
# popd returns somewhere we did not track, so treat it as unknown.
POPD = re.compile(r"^popd\b")


def _sql_file_written_then_run(cmd, segs):
    """Did this command line WRITE a file and then feed it to a SQL client?

    `echo 'DELETE FROM users' > q.sql && psql app -f q.sql` executes the
    statement, but it has no newline and nothing pipes into the client, so the
    whole-line rescan skipped it. Widening the gate to any `&&` before a client
    was too blunt: it re-blocked `npm test -- -t 'delete from cart' && psql -c
    'SELECT 1'`, where the quoted text is a test filter and never reaches SQL.
    """
    fed = set()
    for m in re.finditer(r"\b(?:" + FILE_FED_CLIENT + r")\b"
                         r"[^\n|;&]*?(?:-f|--file)[=\s]+([^\s;&|<>]+)", cmd, re.I):
        fed.add(m.group(1).strip("'\""))
    for m in re.finditer(r"\b(?:" + FILE_FED_CLIENT + r")\b[^\n|;&]*?<\s*([^\s;&|<>]+)",
                         cmd, re.I):
        fed.add(m.group(1).strip("'\""))
    if not fed:
        return False
    names = fed | {os.path.basename(f) for f in fed} | {f.lstrip("./") for f in fed}
    for s in segs:
        m = re.search(r">>?\s*([^\s;&|<>]+)", getattr(s, "raw", str(s)))
        if m and m.group(1).strip("'\"") in names:
            return True
    return False


# (segment, invocation) -> (reason, fix) or None, cheap first, sharing one
# Invocation. Named so tests can pin WHICH rule fired: a boolean cannot, and a
# mutation pass found rules deletable with the suite green because a broader
# rule caught their cases anyway.
SEGMENT_RULES = (
    ("sql", lambda seg, inv: check_sql(seg, local=inv.is_local_db)),
    ("prod-db", lambda seg, inv: check_prod_db(inv.raw, stripped=inv.stripped)),
    ("db-wipe", lambda seg, inv: check_db_wipe(inv.raw, stripped=inv.stripped)),
    ("rm", lambda seg, inv: check_rm(seg)),
    # A quoted literal inside an inline PROGRAM is data, the same way a
    # commit message is. Without stripping them, printing the name of a
    # dangerous command from python was refused while echoing it was not,
    # so writing a test or a runbook about these tools was blocked.
    # Actually RUNNING one from a program is caught by inline-code below.
    ("tools", lambda seg, inv: check_tools(
        strip_quoted(seg)
        if inline_code(inv.unwrapped) and not PROGRAM_EXECUTES.search(seg)
        else seg)),
    ("inline-code", lambda seg, inv: check_inline_code(inv.unwrapped)),
)

_LAST_RULE = [None]


def last_rule():
    """Name of the SEGMENT_RULES entry behind the last block. Test-only.

    None if the block came from git/secrets, or nothing has blocked.
    """
    return _LAST_RULE[0]


# Something that EXECUTES a file it is handed, as opposed to reading it.
# `cat /tmp/c.sh` is a read; `bash /tmp/c.sh` and `source /tmp/c.sh` are not.
RUNS_A_FILE = re.compile(
    r"(^|[\s;&|(])(" + "|".join(sorted(RUNNER_NAMES, key=len, reverse=True))
    + r"|source|\.)\s")


def _written_then_run(segs, cwd):
    """Content written to a file and then executed by a later segment.

    `echo 'git push --force origin main' > /tmp/c.sh; bash /tmp/c.sh` runs the
    push. Every rule saw an echo of some prose and a shell being handed a
    filename, and neither is dangerous on its own.

    `_sql_file_written_then_run` already does exactly this for SQL clients. The
    shell spelling of the same trick had no equivalent, which is the shape of
    most of what is left in the red-team corpus: the guard reasons about one
    command at a time, and these attacks are spread over two.

    Only literal content is recovered, so this cannot resolve what it cannot
    read. That is the same bargain the inline rules make.
    """
    written = {}
    for s in segs:
        raw = getattr(s, "raw", str(s))
        m = re.search(r"^\s*(?:echo|printf|cat)\b(.*?)>>?\s*([^\s;&|<>]+)", raw)
        if not m:
            continue
        quoted = re.findall(r"'([^']*)'|\"([^\"]*)\"", m.group(1))
        body = " ".join(a or b for a, b in quoted) or m.group(1).strip()
        target = m.group(2).strip("'\"")
        if body.strip():
            written[target] = body
            written[os.path.basename(target)] = body
            # ...and the `./name` spelling. Writing `c.sh` then running
            # `bash ./c.sh` is the same two segments, and it did not join up,
            # while `> ./c.sh` then `bash ./c.sh` did.
            written["./" + os.path.basename(target)] = body
    if not written:
        return None
    for s in segs:
        raw = getattr(s, "raw", str(s))
        for tok in tokens(raw):
            name = tok.strip("'\"")
            if name not in written:
                continue
            # Only when something actually RUNS the file: being handed to a
            # shell, sourced, or fed on stdin. `cat /tmp/c.sh` is a read.
            if not RUNS_A_FILE.search(raw) and "<" not in raw:
                continue
            hit = check_command(written[name], cwd)
            if hit:
                return hit
    return None


def _normalise(cmd, cwd):
    """The command as a judgeable string, and a cwd we can trust.

    Returns (cmd, cwd), or None when there is nothing to judge.
    """
    if isinstance(cmd, (list, tuple)):
        parts = [str(c) for c in cmd]
        # `["bash", "-lc", X]` RUNS X, so judge X: it is the same text the
        # string-shaped host sends, and judging it directly is the only way the
        # two hosts can reach the same verdict. Joining instead produced a
        # WRAPPED line that the rules then had to unwrap, and the round trip
        # lost 66 of 1211 verdicts, among them an inline program deleting a
        # system path and a pipe into a shell. The unwrapping is good at what it
        # is for, which is a wrapper the agent actually typed; it should not
        # have to undo an encoding this function chose.
        if (len(parts) >= 3 and parts[1].startswith("-")
                and not parts[1].startswith("--")
                and "c" in parts[1]
                and os.path.basename(parts[0]) in SHELL_NAMES):
            cmd = parts[-1]
        else:
            # shlex.join, not " ".join: the plain join destroys the argument
            # boundaries an argv list already established, so
            # ["mongosh", "--eval", "db.dropDatabase()"] became text with no
            # quoting and nine liability commands stopped blocking. Codex's
            # exec tool is the argv-shaped one, so the plain join meant that
            # host ran weaker rules than the Claude host on the same input.
            cmd = shlex.join(parts)
    if not cmd or not isinstance(cmd, str) or not cmd.strip():
        return None
    cwd = cwd or os.getcwd()
    if not os.path.isdir(cwd):
        # A stale or bogus payload cwd must not be judged against the hook
        # process's own directory, which has nothing to do with the command.
        cwd = "\0unresolvable"
    return cmd, cwd


def _reset_budgets():
    """Forget the last run. OUTERMOST call only.

    The substitution recursion re-enters check_command, and resetting per
    re-entry gave the caller an unbounded subprocess budget: one `$(...)` per
    segment refilled it as fast as it was spent.
    """
    _LAST_RULE[0] = None
    # One call, owned by the module that owns the state. This used to be five
    # .clear() lines reaching into guard_git's private names, and the sixth
    # cache was never on the list: a hand-maintained reset that had already
    # drifted once.
    guard_repo.reset_state()
    _BRACE_BUDGET[0] = MAX_BRACE_WORK


# Returned by a phase that has judged this segment and wants the rest skipped.
# NOT None: three cd paths mean "stop", three more mean "nothing to say", and
# collapsing the two turns fail-closed paths into fail-open with nothing to
# show for it in a test run.
SKIP = object()

UNKNOWN = "\0unresolvable"


class _Line:
    """One command line, and the state the phases thread through it."""

    __slots__ = ("cmd", "cwd", "segs", "piped", "shell_fed", "cwd_stack",
                 "branch_override", "virgin_dirs", "seg", "prose", "seg_cwd")

    def __init__(self, cmd, cwd):
        self.cmd = cmd
        self.cwd = cwd
        # `git init && git add . && git commit -m init` is the standard first
        # commit. The repo does not exist at hook time, so the virgin-repo
        # carve-out could not see it. Filled by _note_git_init.
        self.virgin_dirs = set()
        # A metadata-only command feeding a pipe is not metadata-only: the
        # consumer does the reading. `find . -name .env | xargs cat`.
        self.piped = _piped_segment_indices(cmd)
        # Segments whose output feeds an interpreter. `echo 'rm -rf ~' | sh`
        # is not prose: the "message" IS the command. The pipe is a splitter,
        # so a per-segment regex cannot see this; it comes from the sequence.
        self.shell_fed = _shell_fed_indices(cmd)
        # cwd is scoped per subshell depth: `(cd other && git push)` applies
        # inside the parens and is discarded on the way out, as the shell does.
        self.cwd_stack = [cwd]
        self.branch_override = None
        self.segs = segments(cmd)
        if len(self.segs) > MAX_SEGMENTS:
            self.segs = _cap_segments(self.segs)
        self.seg = None
        self.prose = False
        self.seg_cwd = cwd

    @property
    def here(self):
        """The directory to judge against, with UNKNOWN resolved to the cwd."""
        return self.cwd if self.seg_cwd == UNKNOWN else self.seg_cwd

    @property
    def raw(self):
        """The segment as written, still carrying any `KEY=value` prefix that
        the production-database rule has to see."""
        return getattr(self.seg, "raw", self.seg)


def _phase_cd(line, idx):
    """Track `cd`, so `cd repo && git push` targets repo and not the session.

    Every unresolvable path sets UNKNOWN, which fails closed: leaving the
    previous directory in place is how a stale branch gets trusted.
    """
    seg = line.seg
    depth = getattr(seg, "subshell_depth", 0)
    while len(line.cwd_stack) <= depth:
        line.cwd_stack.append(line.cwd_stack[-1])
    del line.cwd_stack[depth + 1:]
    line.seg_cwd = line.cwd_stack[depth]

    if POPD.match(seg):
        line.cwd_stack[depth] = UNKNOWN
        line.branch_override = None
        return SKIP
    # An unrecognised `cd` (a flag, `--`, a trailing comment) must not leave
    # the previous directory in place.
    if re.match(r"^(cd|pushd)\b", seg) and not CD_PREFIX.match(seg):
        line.cwd_stack[depth] = UNKNOWN
        line.branch_override = None
        return SKIP
    m = CD_PREFIX.match(seg)
    if m:
        line.branch_override = None      # a new directory is a new repo
        d = normalize_path(m.group("dir"))
        cand = d if os.path.isabs(d) else os.path.join(line.here, d)
        cand_norm = os.path.normpath(cand)
        # A `git init` earlier in this line may have created the target; the
        # guard runs before the command does, so isdir() is false but the cd
        # is legitimate. ONLY a `git init` counts: letting `mkdir` count made
        # check_git find no repo there and drop protection outright, so
        # `mkdir sub && cd sub && git commit` was allowed on main.
        # A `git init` LATER on this line will create the target: the hook
        # runs before the command does, so isdir() is false while the cd is
        # perfectly legitimate. This is the shape every new project starts
        # with, and it is what `bootstrap` emits:
        #
        #     mkdir app && cd app && git init && git commit -m init
        #
        # Look FORWARD for that init rather than trusting the `mkdir`. The
        # mkdir is not what makes this safe; the init is. Letting mkdir count
        # made check_git find no repo at the new path and drop protection
        # outright, so `mkdir sub && cd sub && git commit` was allowed on a
        # protected branch, which is the exact hazard this comment used to
        # warn about. With the init required, that line has no init to find
        # and still fails closed.
        #
        # cand_norm is the base for the look-ahead because a bare `git init`
        # in a later segment runs AFTER this cd, so it inits this directory.
        ahead = set()
        if not os.path.isdir(cand) and cand_norm not in line.virgin_dirs:
            for nxt in line.segs[idx + 1:]:
                _note_git_init(nxt, cand_norm, ahead)
        line.cwd_stack[depth] = cand_norm if (
            os.path.isdir(cand) or cand_norm in line.virgin_dirs
            or cand_norm in ahead) else UNKNOWN
        return SKIP
    return None


def _phase_prose(line, idx):
    """Decide whether this segment is a message, and rewrite it if it is not.

    MUTATES `line.seg`, and must run before any rule. An `echo`/`printf` whose
    output feeds an interpreter is not prose: the quoted text IS the command,
    and `echo 'rm -rf ~' | sh` was allowed because the echo read as prose and
    the `sh` segment held nothing. The git rules come first, so a later rewrite
    would still leave them looking at one shlex token holding the payload.
    """
    line.prose = bool(MESSAGE_BEARING.search(line.seg))
    if line.prose and idx in line.shell_fed:
        line.prose = False
        seg = line.seg
        _uq = str(seg).replace(chr(34), "").replace(chr(39), "")
        _uqraw = getattr(seg, "raw", str(seg)).replace(chr(34), "").replace(chr(39), "")
        line.seg = Segment(_uq, _uqraw, getattr(seg, "subshell_depth", 0))
    return None


def _phase_secrets(line, idx):
    """Credentials, which apply to prose-bearing commands too.

    For a commit message or a grep pattern, scan only the part OUTSIDE the
    quotes and skip the loose scan, so `git commit -m "note about .env
    handling"` works while `git add .env` does not.
    """
    raw = line.raw
    hit = check_secrets_cmd(strip_quoted(raw) if line.prose else raw,
                            loose=not line.prose,
                            piped=(idx in line.piped), stripped=line.seg)
    if hit:
        return hit
    # A substitution inside a commit message still EXECUTES, so scan its
    # contents even for prose. Only the contents: `--body "... $(date)"` stays.
    if "$(" in raw or "`" in raw:
        return check_substitutions(raw)
    return None


def _phase_git(line, idx):
    """The git rules, and the three pieces of state they leave behind."""
    hit = check_git(line.seg, line.here,
                    None if line.seg_cwd == UNKNOWN else line.branch_override,
                    unknown_cwd=(line.seg_cwd == UNKNOWN),
                    virgin_dirs=line.virgin_dirs)
    if hit:
        return hit
    _note_git_init(line.seg, line.here, line.virgin_dirs)
    # Only a REAL checkout grants the override, and only from a non-prose
    # segment. An echoed one must not.
    if not line.prose:
        line.branch_override = _note_checkout(
            line.seg, line.here, line.seg_cwd == UNKNOWN, line.branch_override)
    return None


def _phase_nested(line, idx):
    """Payloads that are themselves commands, judged one level deep.

    A here-string carries a program inside ONE shlex token, so every
    token-based rule looked straight past it: `bash <<< 'cmd'` runs cmd.

    The substitution half was KEPT through the 2026-08-08 cut, deliberately.
    Everything else removed that day was anti-evasion; this is not. `echo
    "Deleted: $(rm -rf /tmp/build)"` runs the rm, and an agent reaches that by
    accident rather than by hiding.
    """
    if depth_guard[0] != 0:
        return None
    raw = line.raw
    bodies = [p for p in fed_payloads(raw) if p.strip()]
    if "$(" in raw or "`" in raw:
        bodies += [b for b in _substitution_bodies(raw) if b.strip()]
    if not bodies:
        return None
    depth_guard[0] = 1
    try:
        for body in bodies:
            # Pass seg_cwd THROUGH, including UNKNOWN. Mapping it to None made
            # it os.getcwd(), so `popd; echo "$(git commit -am x)"` was judged
            # against the hook's own directory.
            hit = check_command(body, line.seg_cwd)
            if hit:
                return hit
    finally:
        depth_guard[0] = 0
    return None


def _phase_writes(line, idx):
    """Writes that hand over control rather than storing data.

    Only the control-path question: the credential rules already saw this
    segment, with the exemptions that keep `cat .env.example > .env` working.
    """
    for target in redirect_targets(line.raw):
        hit = check_control_path(normalize_path(target), target)
        if hit:
            return hit
    # RAW, not seg. For an interpreter the segment may have been replaced
    # by its `-e` PAYLOAD, so `perl -pi -e s/a/b/ <guard file>` arrived here
    # as the program `s/a/b/` with the path it rewrites already gone.
    return check_guard_mutation(line.raw)


def _phase_rules(line, idx):
    """The segment rule table. Prose stops here."""
    if line.prose:
        return SKIP
    # One Invocation per segment. Locality is judged on RAW: segments() strips
    # the KEY=value prefixes where a retargeted host hides.
    inv = Invocation(line.raw, line.seg)
    for name, rule in SEGMENT_RULES:
        hit = rule(line.seg, inv)
        if hit:
            _LAST_RULE[0] = name
            return hit
    return None


# ORDER IS LOAD-BEARING. A tuple, not a dict, and not sorted: the prose phase
# rewrites the segment and the git rules must see the rewrite, so moving either
# reopens `echo 'rm -rf ~' | sh`, which floor.py pins.
SEGMENT_PHASES = (
    _phase_cd,
    _phase_prose,
    _phase_secrets,
    _phase_git,
    _phase_nested,
    _phase_writes,
    _phase_rules,
)


def check_command(cmd, cwd=None):
    """Run every command rule, per segment. Returns (reason, fix) or None."""
    prepared = _normalise(cmd, cwd)
    if prepared is None:
        return None
    cmd, cwd = prepared
    if depth_guard[0] == 0:
        _reset_budgets()

    cmd, oversize = _oversize_verdict(cmd)
    if oversize:
        return oversize

    # WHOLE-command, before segmentation. `python3 - <<'PY' ... PY` runs its
    # body exactly as `python3 -c '...'` does, but segments() splits that body
    # into one segment per line, so the per-segment inline-code rule was handed
    # a line at a time and never saw a program. The delete half of that rule
    # was therefore off for every heredoc spelling: shutil.rmtree('/var/www')
    # blocked as `-c` and ran as a heredoc. The credential half looked fine
    # only because the path scanner is text-shaped and finds a path anywhere.
    #
    # This also makes true a sentence in evals/redteam-candidates.txt that was
    # half false: that a heredoc body is re-entered and still refuses system
    # deletes and credential reads.
    body = interpreter_heredoc_body(cmd)
    if body:
        hit = check_inline_code("", code=body)
        if hit:
            return hit

    # `$(pwd)` and the backtick form mean exactly `$PWD`, but `(` and `)` are
    # segment splitters, so `rm -rf $(pwd)` arrived as `rm -rf $` plus `pwd` and
    # no rule ever saw a path. Normalise to the spelling the rules understand.
    cmd = re.sub(r"\$\(\s*pwd\s*\)|`\s*pwd\s*`", "$PWD", cmd)

    # Resolve what can be resolved. Both of these put the dangerous word behind
    # something the rules do not evaluate, and the answer is to evaluate it
    # once here rather than to teach every rule about variables and
    # substitutions separately.

    cmd = blank_inert_heredocs(cmd)

    # Whole-line, before the per-segment phases: a pipeline consumer cannot see
    # the producer that makes the delete dangerous.
    hit = check_xargs_rm(cmd)
    if hit:
        return hit

    line = _Line(cmd, cwd)
    for idx, seg in enumerate(line.segs):
        line.seg, line.prose = seg, False
        for phase in SEGMENT_PHASES:
            hit = phase(line, idx)
            if hit is SKIP:
                break
            if hit:
                return hit

    # The whole-line rescan exists for ONE case: a statement wrapped across
    # real newlines, so its verb and its WHERE land in different segments.
    # Joining every segment and judging the join meant a SQL client anywhere on
    # the line made an unrelated quoted argument elsewhere look like a
    # statement, so `prisma generate && npm test -- -t 'delete from cart'` was
    # blocked. So: only when there are newlines to have split one, or when a
    # statement is PIPED into a client (`echo "DROP TABLE x" | psql app` is two
    # segments and the client is in the second one).
    # The shell spelling of the same trick: write a script, then run it.
    hit = _written_then_run(line.segs, line.cwd)
    if hit:
        return hit
    if "\n" in cmd or re.search(r"\|\s*\S*(?:" + FILE_FED_CLIENT + r")\b", cmd, re.I) \
            or _sql_file_written_then_run(cmd, line.segs):
        whole = re.sub(r"\s+", " ",
                       " ; ".join(getattr(s, "raw", str(s)) for s in line.segs))
        if is_sql_context(whole) or not MESSAGE_BEARING.search(whole.strip()):
            hit = check_sql(whole)
            if hit:
                return hit
            # ...and the non-SQL verbs, for the same reason. A statement
            # written to a file and then fed to a client executes whether or
            # not it is SQL, and this path only ever asked check_sql, so
            # `... > f.js && mongo app < f.js` ran a collection drop that the
            # same verb typed inline would have blocked.
            hit = check_db_wipe(whole, anchored=False)
            if hit:
                return hit
    return None


# The guard's own installed files. Writing these is how a guard stops being a
# guard, and AGENTS.md's "do not ask the user to disable a hook" was the only
# guardrail in that file with nothing enforcing it.
#
# READS stay allowed: understanding and auditing the installed rules is
# legitimate and frequent.
# git's control plane: the files that decide what a later git command does.
