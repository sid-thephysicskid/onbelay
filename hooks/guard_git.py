#!/usr/bin/env python3
"""Git rules, and the repository state they need."""
import os
import re
import subprocess

from guard_repo import (  # noqa: F401
    MAX_GIT_CALLS,
    _GIT_CALLS,
    current_branch,
    has_commits,
    is_branch,
    is_git_repo,
    is_virgin_repo,
    rebase_in_progress,
    reset_state,
)
from guard_parse import (  # noqa: F401
    asks_for_help,
    normalize_path,
    strip_quoted,
    tokens,
)

# Overridable, because the hardcoded list is wrong in both directions for real
# teams. A solo engineer working on `main` in their own repository had no escape
# but uninstalling, and a team whose protected branch is `develop` or `staging`
# got no protection at all.
#
# Read from the environment the HOOK runs in, which is the user's session, not
# a shell an agent spawns: a `export` inside one tool call does not reach the
# next hook process, so this is a decision the human makes in their profile
# rather than a switch the agent can flip mid-task. Empty disables the branch
# rules entirely, which is a choice the user is allowed to make and which
# `--check` reports so it cannot be forgotten.
_DEFAULT_PROTECTED = ("main", "master", "trunk", "release", "production", "prod")
_override = os.environ.get("AGENT_GUARD_PROTECTED_BRANCHES")
PROTECTED_BRANCHES = (
    {b.strip() for b in _override.split(",") if b.strip()}
    if _override is not None else set(_DEFAULT_PROTECTED))

# The three ref-MOVING rules below need the protected set as a regex
# alternation. They used to carry a hand-typed copy of _DEFAULT_PROTECTED
# instead, which meant AGENT_GUARD_PROTECTED_BRANCHES did not reach them and
# was wrong in both directions at once: a team on `develop` got the protection
# they had configured for `commit` and `push` and none of it for `branch -f`,
# `checkout -B` or `update-ref`, and a user who set the variable EMPTY to turn
# the rules off, exactly as the README says they may, still could not move
# `main`. The banner install.sh prints to confirm the setting took effect was
# telling them something untrue.
#
# Longest first, so no short name shadows a longer one inside the group. The
# same reason _alt() sorts in guard_parse.
# `or "(?!)"`: an EMPTY protected set must make these rows match nothing. An
# empty alternation is `(?:)`, which matches the empty string, so the rules
# would have fired on every branch name at the exact moment the user asked for
# them to be off. `(?!)` is a negative lookahead on empty and can never match.
_PROT_ALT = "|".join(sorted((re.escape(b) for b in PROTECTED_BRANCHES),
                            key=len, reverse=True)) or "(?!)"

# Shapes this module blocks, spelled loosely enough to be recognised in text
# that is never parsed into segments: the discarded middle of an oversized
# command. guard_rules concatenates one of these tuples from each rule module.
#
# It lives HERE, next to the rules, because the single copy that used to live
# in the parser was hand-maintained and went stale. Sixteen blocked classes,
# including every irreversible publish, were allowed when padded past the
# analysis window. A rule added below without a signal here is a rule that
# stops applying at 40KB, so add both or neither.
MIDDLE_SIGNALS = (
    r"\bgit\b[^\n]{0,80}--force(?![-\w])",
    r"\breset\s+--hard",
    r"\bclean\s+-[\w-]*f",
    r"\bbranch\s+-D",
    r"\bgit\b[^\n]{0,80}\b(commit|push)\b",
    r"\bgit\b[^\n]{0,40}(checkout|restore)\s+(\.|:/|\*)",
    r"\bstash\s+drop",
    r"\bworktree\s+remove\s+[^\n]{0,20}-",
    r"\bfilter-(branch|repo)\b",
    r"\breflog\s+expire\b",
    r"\bupdate-ref\s+-d\b",
    # Added with the rules below, per the note above: a rule with no
    # signal here is a rule that stops applying once the line is padded
    # past the analysis window. These five had rules and no signal.
    r"\bbranch\s+-[\w-]*f(?![-\w])",
    r"\bcheckout\s+-[\w-]*B(?![-\w])",
    r"\bupdate-ref\s+refs/heads/",
    r"\bsymbolic-ref\b",
    r"\bcore\.hooksPath\b",
)

# Every git verb that writes a commit. `commit` alone left four ways onto a
# protected branch, and a `git merge` on main is exactly what the rule is for.
COMMIT_MAKING = {"commit", "merge", "revert", "cherry-pick", "am"}

# Forms of those verbs the protected-branch rule must not fire on. NOT the same
# as "writes no commit": `--continue` does write one, and is exempt anyway.
#   --continue/--abort/--skip/--quit  finish or unwind something in flight, and
#                                     blocking them strands the user with no
#                                     legal exit, which /unstick depends on.
#                                     `--continue` is therefore a known hole,
#                                     pinned as one in evals/guard_claims.json
#   --ff-only                         fast-forward writes no new history; this
#                                     is how you sync a protected branch, and
#                                     blocking the safe spelling while `git
#                                     pull` stays allowed is pure cry-wolf
#   --squash                          stages the change without committing it
#   --show-current-patch, -h, --help  pure inspection
# Verb-aware on purpose. Matching the whole segment meant `--squash`, which
# means "stage without committing" to `merge`, also exempted `git commit
# --squash=<ref>`, which writes a real commit.
_NOT_A_COMMIT_ANY = re.compile(r"--(help)\b|(^|\s)-h(\s|$)")

_NOT_A_COMMIT_BY_VERB = {
    # `--no-commit`/`-n` stages the result and stops, which is the same
    # "writes no commit" case the rest of this table covers.
    "merge": r"--(continue|abort|quit|ff-only|squash|no-commit)\b|(^|\s)-n(\s|$)",
    "revert": r"--(continue|abort|skip|quit|no-commit)\b|(^|\s)-n(\s|$)",
    "cherry-pick": r"--(continue|abort|skip|quit|no-commit)\b|(^|\s)-n(\s|$)",
    "am": r"--(continue|abort|skip|quit|show-current-patch)\b",
    "commit": r"(?!)",          # nothing exempts a plain commit
}

def _args_after(seg, *verbs):
    """Tokens following the first of `verbs` present in this segment, or None.

    None means the verb is not a token here, which is different from a verb
    with no arguments and is what several callers key off.
    """
    toks = tokens(seg)
    kw = next((k for k in verbs if k in toks), None)
    return None if kw is None else toks[toks.index(kw) + 1:]


def _safe_force_with_lease(seg, branch):
    """True only for the one history rewrite this suite deliberately allows.

    The permitted form pins the currently checked-out, non-protected branch
    to a full commit ID and names no alternate refspec. A bare lease relies on
    mutable remote-tracking state, while a lease for one ref plus a push of
    another ref does not protect the ref being rewritten.
    """
    args = _args_after(seg, "push") or []
    lease = [i for i, arg in enumerate(args)
             if arg.startswith("--force-with-lease")]
    if len(lease) != 1 or not branch or branch in PROTECTED_BRANCHES:
        return False
    match = re.fullmatch(
        r"--force-with-lease=([^:]+):([0-9a-fA-F]{40})", args[lease[0]])
    if not match or match.group(1) != branch:
        return False
    # The lease pins the current branch to a full SHA, which is the whole
    # protection. What follows may name the REMOTE and a refspec for that same
    # branch, because that is how the command is actually typed and how /ship
    # step 7 teaches it. Requiring the lease to be the only argument meant a
    # user who followed this rule's own fix line, then appended `origin
    # <branch>` from muscle memory, got the identical refusal again. A guard
    # whose remediation does not unblock you is the one people switch off.
    rest = [a for i, a in enumerate(args)
            if i != lease[0] and not a.startswith("-")]
    for i, arg in enumerate(rest):
        if i == 0 and ":" not in arg:
            continue                                   # the remote
        if arg in (branch, "HEAD:" + branch, branch + ":" + branch):
            continue                                   # this branch, no other
        return False
    return True

def _exempt_from_branch_rule(sub_cmd, seg):
    # Only in the verb's own flags, and only before a redirect or a `--`.
    # Matching the whole segment meant `git commit -am pwn > -h` was exempt,
    # because the redirect TARGET was named `-h`.
    after = _args_after(seg, sub_cmd)
    if after is not None:
        for stop in ("--", ">", ">>", "<", "|"):
            if stop in after:
                after = after[:after.index(stop)]
        if _NOT_A_COMMIT_ANY.search(" " + " ".join(after) + " "):
            return True
    elif _NOT_A_COMMIT_ANY.search(seg):
        return True
    pat = _NOT_A_COMMIT_BY_VERB.get(sub_cmd)
    return bool(pat and re.search(pat, seg))

# Tools that make a commit and a tag WITHOUT running `git` themselves, so
# git_invocations never sees them. `npm version patch` on main is the standard
# way a release lands on a protected branch by accident, and /ship documents it
# as the trap it is.
VERSION_BUMPER = re.compile(
    # npm/pnpm/bun need a NEW VERSION argument to bump: a bare `npm version`
    # only prints. yarn takes it as a flag, so it is matched on its own.
    r"(^|[\s;&|(])(npm|pnpm|bun)\s+version\s+(?!-)\S(?![^\n]*--no-git-tag-version)"
    r"|(^|[\s;&|(])yarn\s+version\b(?![^\n]*--no-git-tag-version)"
    r"|(^|[\s;&|(])(lerna|nx)\s+version\b"
    r"|(^|[\s;&|(])(standard-version|commit-and-tag-version)\b"
    r"|(^|[\s;&|(])(bumpversion|bump2version)\b"
    r"|(^|[\s;&|(])cargo\s+release\b")

# One segment this long is not a command a person typed. The regex-heavy
# git scans run ~23 patterns per segment, so 40KB in one segment cost 5s,
# past the hook timeout, and a timeout fails open.
MAX_SEGMENT_SCAN = 8 * 1024

MAX_GIT_INVOCATIONS = 50

def git_invocations(seg):
    """Every git call in a segment, as (subcommand, repo_dir_or_None).

    Finds git by basename so `/usr/bin/git` counts, and parses global options
    so `git -C /repo push` is seen as a push against /repo.
    """
    toks = tokens(seg)
    found = []
    for i, tok in enumerate(toks):
        if os.path.basename(tok.strip("(){};")) != "git":
            continue
        j = i + 1
        repo = None
        # `GIT_DIR=/other/repo/.git git commit` retargets the whole command, so
        # the branch has to be read from there, not from the cwd.
        if i and toks[i - 1].startswith("GIT_DIR="):
            repo = re.sub(r"/\.git/?$", "", toks[i - 1].split("=", 1)[1])
        while j < len(toks) and toks[j].startswith("-"):
            t = toks[j]
            if t == "-C" and j + 1 < len(toks):
                repo = toks[j + 1]; j += 2; continue
            if t.startswith("--git-dir="):
                repo = t.split("=", 1)[1]; j += 1; continue
            if t in ("--git-dir", "--work-tree") and j + 1 < len(toks):
                if t == "--git-dir":
                    repo = toks[j + 1]
                j += 2; continue
            if t == "-c" and j + 1 < len(toks):
                j += 2; continue
            j += 1
        if j < len(toks):
            found.append((toks[j], repo))
            if len(found) >= MAX_GIT_INVOCATIONS:
                break
    return found

# Subcommands where git defines a dry run that writes NOTHING. Scoped on
# purpose, not applied to every verb: the short `-n` is not universal, and
# `git commit -n` is --no-verify, which really does commit. Honouring `-n`
# there would turn the protected-branch rule off with one flag.
#   git-clean(1): "-n, --dry-run  Don't actually remove anything ...
#     Configuration variable clean.requireForce is ignored, as nothing will
#     be deleted anyway." So `git clean -n -f` deletes nothing.
#   git-push(1):  "-n, --dry-run  Do everything except actually send the
#     updates."
DRY_RUN_SUBS = ("push", "clean")


def _is_dry_run(seg, sub):
    """Does this invocation carry a dry-run flag that makes it a preview?

    By TOKEN POSITION, not by searching the text. A bare search matched the
    flag inside a pathspec after `--`, inside another flag's value, and inside
    a quoted filename, so `git clean -fd -- --dry-run` read as a preview and
    deleted. Everything after `--` is an operand, never a flag.
    """
    if sub not in DRY_RUN_SUBS:
        return False
    args = _args_after(seg, sub) or []
    for arg in args:
        if arg == "--":
            return False
        if arg == "--dry-run":
            return True
        # A short cluster: -n, -nd, -xdn, -nf. Not a long option, so one dash.
        if re.fullmatch(r"-[a-zA-Z]*n[a-zA-Z]*", arg):
            return True
    return False


DESTRUCTIVE_GIT = (
    (r"\breset\s+.*--hard", "git reset --hard (discards committed and staged work)",
     "git stash  or  git revert <sha>"),
    (r"\bclean\s+.*-\w*f", "git clean -f (deletes untracked files permanently)",
     "git clean -n first to preview, then delete the specific files you meant"),
    # The two `checkout … .` regexes that used to sit here are gone. They only
    # ever knew `.` and `./`, which is why _checkout_touches_worktree was
    # written; that function parses the flags and covers every spelling,
    # including `checkout HEAD -- .`. tests/mutate.py confirmed all five
    # spellings still block without them: leftover, not defence in depth.
    (r"\bbranch\s+(-\w*D\b|--delete\b[^\n]{0,40}--force\b|--force\b[^\n]{0,40}--delete\b)", "git branch -D (force-deletes an unmerged branch)",
     "git branch -d  (refuses if unmerged, which is the point)"),
    # `--mirror` makes the remote exactly match local refs: it force-updates
    # every branch and deletes the ones you do not have. The README
    # promises "force push in any form", and this is the most total form.
    (r"\bpush\b[^\n]{0,60}--mirror\b", "git push --mirror (force-updates every ref and deletes remote branches)",
     "push the one branch you mean: git push origin <branch>"),
    (r"\b(filter-branch|filter-repo)\b", "history rewrite", "open a PR and discuss first"),
    (r"\bstash\s+(drop|clear)\b", "dropping stashed work", "git stash list  and apply what you need"),
    (r"\breflog\s+expire\b", "reflog expiry (destroys the recovery net)", "leave the reflog alone"),
    (r"\bupdate-ref\s+-d\b", "deleting a ref directly", "use the matching git command"),
    # Moving a protected branch WITHOUT committing or pushing to it. A red-team
    # pass found all three: the branch rules only ever watched `commit` and
    # `push`, so the three documented ways to relocate a ref went straight
    # through, from any branch, including the one everyone else pulls.
    # These are not exotic. An agent reaching for `checkout -B` to "reset main
    # to origin" is an ordinary mistake, which is exactly this guard's remit.
    (r"\bbranch\s+(-\w*f\b|--force\b)[^\n]{0,40}\b(?:" + _PROT_ALT + r")\b",
     "git branch -f on a protected branch (moves it under everyone else)",
     "branch somewhere else, or open a PR"),
    (r"\b(checkout|switch)\s+(-\w*[BC]\b|--force-create\b)\s+(?:" + _PROT_ALT + r")\b",
     "git checkout -B on a protected branch (resets it to wherever you are)",
     "git checkout <branch> without -B, or use a new branch name"),
    (r"\bupdate-ref\s+(--\S+\s+)*refs/heads/(?:" + _PROT_ALT + r")\b",
     "moving a protected branch ref directly",
     "open a PR; a ref write bypasses every review this repo has"),
    (r"\bsymbolic-ref\s+(?!--\S)\S+\s+refs/",
     "repointing HEAD by hand (the next commit lands on a branch you did not check out)",
     "git checkout <branch>, so the working tree and the ref agree"),
    # Aliases and hooksPath are the two git settings that turn a later,
    # innocent-looking command into something else. `git -c alias.x='commit'
    # x` and `git config core.hooksPath /tmp/evil` both defeat every rule in
    # this file, because the rule reads the command it was given and the
    # damage is done by what runs afterwards.
    # `(^|\s)-c`, not `\b-c`: there is no word boundary between a space and a
    # hyphen, so the `\b` form never matched the flag at all.
    # `\S*\s+\S` on the config half: a config line with nothing after the key
    # is a READ, and `--unset` REMOVES the hazard. Matching the key alone
    # refused `git config --get core.hooksPath`, which is the first thing
    # anyone runs when a hook will not fire, and `git config --unset alias.wip`,
    # which is the fix. `git config --list` was allowed the whole time, so the
    # rule was inconsistent as well as wrong. The `-c` half needs no such test:
    # it carries its value inline as `-c alias.x=...`.
    (r"(^|\s)-c\s+alias\.|(^|\s)config\b[^\n]{0,40}\balias\.\S*\s+\S",
     "defining a git alias (an alias runs a different command than the one written)",
     "run the command you mean, spelled out"),
    (r"(^|\s)config\b[^\n]{0,40}\bcore\.hooksPath\b\s+\S",
     "repointing git's hooks directory (every later git command runs code from there)",
     "leave core.hooksPath alone; put repo hooks in .git/hooks yourself"),
    # Both spellings, in either order. The long-flag-only form let `git worktree
    # remove -f wt` through, and -f is git's documented short form.
    (r"\bworktree\s+remove\s+(.*\s)?-(-force\b|[A-Za-z]*f\b)",
     "force-removing a worktree with live changes",
     "git worktree remove without --force, and commit or stash first"),
)

def _is_whole_tree(tok):
    """Does this pathspec mean 'everything'?

    `.`, `./`, `:/`, and `*` are all the whole tree. Matching the token
    literally let `git restore ./` and `git restore '*'` through.
    """
    t = tok.strip().strip("'\"")
    if t in ("*", "*/", ":/", ":", ":/.", ":(top)", ""):
        return True
    if t.startswith(":(") and "top" in t.split(")")[0]:
        return True
    t = t.rstrip("/") or "."
    return os.path.normpath(t) in (".", "..")

def _checkout_target(seg):
    """The branch a plain `git checkout X` / `git switch X` moves onto.

    None when the segment names a path, a ref that is not a branch name, or
    nothing at all, which puts the caller back on "ask git" rather than
    trusting a stale override.
    """
    rest = _args_after(seg, "checkout", "switch")
    if rest is None:
        return None
    # `--detach` lands you on a detached HEAD, not on the named branch, so the
    # name must not become the override.
    if "--detach" in rest or "-d" in rest:
        return None
    if "--" in rest:
        # `git checkout <branch> -- <path>` restores a file from that branch
        # and leaves you where you are. Not a switch, so no override to take,
        # in either direction.
        return None
    names = [x for x in rest if not x.startswith("-")]
    if len(names) != 1:
        return None
    # No quote-stripping: the caller strips every quote before this runs.
    name = names[0]
    # A SHA, a path, or a remote-tracking ref is not a branch to trust.
    if "~" in name or "^" in name or ":" in name:
        return None
    return name

def _checkout_touches_worktree(seg):
    """`git checkout <tree-wide-pathspec>` discards the working tree.

    The regexes knew `.` and `./` only, so `git checkout :/` and
    `git checkout *` slipped past while `git restore :/` was caught.
    """
    rest = _args_after(seg, "checkout", "switch")
    if not rest:
        return False
    # `git checkout -b x` and `git checkout <branch>` are not path operations.
    if any(x in ("-b", "-B", "--orphan") for x in rest):
        return False
    # ...but -f/--force/--discard-changes discards the working tree whatever
    # the target is.
    if any(x in ("-f", "--force", "--discard-changes") or
           (re.fullmatch(r"-[A-Za-z]+", x) and "f" in x[1:]) for x in rest):
        return True
    paths = [x for x in rest if not x.startswith("-") and x != "--"]
    # a bare `git checkout <ref>` names one ref, not a pathspec
    if "--" not in rest and len(paths) == 1 and not _is_whole_tree(paths[0]):
        return False
    return any(_is_whole_tree(x) for x in paths)

def _restore_touches_worktree(seg):
    """True when `git restore ... .` would discard working-tree changes.

    `--staged` ALONE only unstages, which is a daily command. Anything else
    touching `.` destroys work. Decided on parsed flags, not a regex: the
    regex missed `-- .`, `--source=HEAD .`, `--worktree --staged .`, and `-SW .`.
    """
    rest = _args_after(seg, "restore")
    if rest is None:
        return False
    paths = [x for x in rest if not x.startswith("-") and x != "--"]
    if not any(_is_whole_tree(x) for x in paths):
        return False
    staged = worktree = False
    for x in rest:
        if x == "--staged" or (re.fullmatch(r"-[A-Za-z]+", x) and "S" in x[1:]):
            staged = True
        if x == "--worktree" or (re.fullmatch(r"-[A-Za-z]+", x) and "W" in x[1:]):
            worktree = True
    return worktree or not staged

def check_git(seg, cwd, branch_override=None, unknown_cwd=False, virgin_dirs=()):
    if len(seg) > MAX_SEGMENT_SCAN:
        seg = seg[:MAX_SEGMENT_SCAN]
    # Documentation runs nothing. check_tools has had this exemption for as long
    # as it has existed; check_git never got it, so `git filter-branch --help`
    # was refused as a history rewrite and `git help filter-branch` with it.
    if asks_for_help(seg):
        return None
    calls = git_invocations(seg)
    if not calls:
        # A version bumper runs no `git` of its own, so the loop below never
        # sees it, but it writes a commit and a tag all the same.
        # Cheap substring gate first. The alternation below is backtracking-
        # prone, and running it on every git-free segment of a large payload
        # cost more than the rule is worth.
        if not any(w in seg for w in ("version", "release", "bump")):
            return None
        if VERSION_BUMPER.search(seg) and not unknown_cwd and is_git_repo(cwd) \
                and current_branch(cwd) in PROTECTED_BRANCHES:
            return ("a version bump that commits and tags, on a protected branch.",
                    "bump on your feature branch, or cut the release from the "
                    "merge commit: gh release create <tag> --target <base>")
        return None

    # `GIT_DIR=/other/repo/.git git commit` retargets the command, and
    # segments() strips the assignment off before the rules see it. Read it
    # from the untouched text and fail closed: the branch there is unknowable
    # from here, and unknown is protected.
    if re.search(r"(^|\s)GIT_DIR=", getattr(seg, "raw", seg)):
        unknown_cwd = True

    push_scanned = False
    for sub, repo in calls:
        # Resolve -C against the PAYLOAD cwd, not the hook process cwd.
        target = os.path.join(cwd, normalize_path(repo)) if repo else cwd
        target = os.path.normpath(target)
        # An earlier segment in this same line may have created and switched to
        # a branch. Judge against that, not against where the line started.
        # A `-C` target the guard cannot resolve is UNKNOWN, not "no repo".
        # `git -C ${PWD} push` on main took the no-repo path and lost
        # protection entirely.
        unresolved_repo = bool(repo) and bool(re.search(r"[$`*?]", repo))
        if unresolved_repo:
            unknown_cwd = True
        if unknown_cwd and (not repo or unresolved_repo):
            branch = None      # unknown fails closed below
        elif not is_git_repo(target):
            # Not a repo: git refuses BRANCH operations on its own, so those
            # checks are noise here. Everything else still applies, because
            # GIT_DIR= and --work-tree can reach a real repo from this cwd.
            branch = None
        else:
            branch = branch_override if (branch_override and not repo) else current_branch(target)

        no_repo = not unknown_cwd and not is_git_repo(target)
        # Unknown branch fails CLOSED: a bad path must not drop protection.
        # No repo here means no branch to protect; unknown still fails closed.
        on_protected = False if no_repo else ((branch in PROTECTED_BRANCHES) if branch else True)

        # A detached HEAD is not a protected branch, but a commit made there is
        # orphaned by the next checkout, which is a worse outcome than the one
        # the branch rule prevents. `git bisect run` and an interactive rebase
        # both leave you here, and `rev-parse --abbrev-ref` answers the literal
        # string "HEAD", so the branch check reads it as an ordinary name.
        # `rebase --continue` and `merge --continue` are unaffected: their
        # subcommand is not "commit", which is what /unstick relies on.
        if sub == "commit" and branch == "HEAD" and not no_repo \
                and not rebase_in_progress(target) \
                and not (target in virgin_dirs or is_virgin_repo(target)):
            return ("commit on a detached HEAD (the commit is orphaned by the next checkout).",
                    "git bisect reset, or git checkout -b fix/<name> to keep the work")

        # COMMIT_MAKING and _NOT_A_COMMIT_BY_VERB carry the reasoning for
        # which verbs land here and which forms of them are exempt.
        # strip_quoted, not the raw segment: matching the message let
        # `git commit -m "fix: handle --abort path"` through on main, and that
        # is an ordinary thing for a message to say.
        if sub in COMMIT_MAKING and on_protected \
                and not _exempt_from_branch_rule(sub, strip_quoted(seg)):
            # An unborn HEAD makes `rev-parse --abbrev-ref` fail, so branch is
            # None here even though the repo is fine. Key off the commit count,
            # not the branch name, or bootstrap's first commit is blocked.
            if target in virgin_dirs or is_virgin_repo(target):
                pass  # a repo with no commits has no history to protect
            else:
                where = branch or "an undeterminable branch"
                verb = "commit" if sub == "commit" else f"`git {sub}`"
                return (f"{verb} directly to '{where}'.",
                        "git checkout -b feature/<name>   (branch there, then open a PR)")

        if sub == "push":
            # A dry-run push sends nothing, so every push rule below is moot
            # for it. `continue`, not `return None`: a later invocation on the
            # same line still has to be judged.
            if _is_dry_run(seg, sub):
                continue
            # Quotes REMOVED before the refspec scans. They are not part of the
            # refspec, and `git push origin 'main'` was allowed while
            # `git push origin main` blocked. Also normalise `refs/heads/main`
            # to `main` so the branch list matches the fully-qualified spelling.
            seg = re.sub(r"(^|[\s+:])refs/heads/", r"\1",
                         seg.replace('"', "").replace("'", ""))
            push_args = _args_after(seg, "push") or []
            if "--all" in push_args:
                return ("git push --all (can update a protected branch that is not checked out).",
                        "push the one feature branch you mean: git push -u origin <branch>")
            if any(arg.startswith("--force-with-lease") for arg in push_args) \
                    and not _safe_force_with_lease(seg, branch):
                return ("an unpinned or mismatched force-with-lease push.",
                        "use git push --force-with-lease=<current-branch>:<full-before-sha> "
                        "after inspecting your own open PR branch")
            if re.search(r"--force(?![-\w])", seg) or re.search(r"(?<![\w-])-\w*f\w*(?=\s|$)", seg):
                return ("force push.",
                        "git push --force-with-lease  (allowed on your own PR branch, never on a protected one)")
            # A leading + forces, with or without a colon: `+main` and
            # `+HEAD:main` are both force pushes.
            if re.search(r"(^|[\s'\"])\+[\w./-]", seg):
                return ("force push by refspec (the leading + forces it).",
                        "push normally, or --force-with-lease on your own branch")
            for b in (() if push_scanned else PROTECTED_BRANCHES):
                if re.search(rf"(--delete\s+|:){re.escape(b)}(\s|$)", seg) \
                   or re.search(rf":refs/heads/{re.escape(b)}(\s|$)", seg):
                    return (f"pushing directly to or deleting '{b}' by refspec.", "open a PR instead")
                # `git push origin main` from anywhere
                if re.search(rf"\bpush\b[^|;]*\s{re.escape(b)}(\s|$)", seg) and "HEAD:" not in seg:
                    return (f"pushing directly at '{b}'.",
                            "push your feature branch and open a PR")
            push_scanned = True
            if on_protected:
                where = branch or "an undeterminable branch"
                return (f"push from '{where}'.",
                        "push a feature branch and open a PR: git push -u origin feature/<name>")

        if sub in ("checkout", "switch") and _checkout_touches_worktree(seg):
            return ("git checkout . (discards all local changes)",
                    "git stash  to keep the changes recoverable")

        if sub == "restore" and _restore_touches_worktree(seg):
            return ("git restore . (discards all local changes)",
                    "git restore --staged .  if you only meant to unstage, "
                    "or git stash to keep the changes recoverable")

        # A commit/tag MESSAGE may legitimately name a destructive command, so
        # scan the segment with quoted runs removed.
        scan = strip_quoted(seg) if sub in (
            "commit", "tag", "notes", "log", "show", "grep", "blame") else seg
        if _is_dry_run(seg, sub):
            continue
        for pat, what, fix in DESTRUCTIVE_GIT:
            if re.search(pat, scan):
                return (what, fix)
    return None

# `git checkout -b x && git commit ...` is the fix this guard itself recommends.
# Without tracking the new branch, the commit is judged against the branch the
# line started on, and the recommended fix gets blocked.
# Handles the plain form and combined short flags: -b, -q -b, and -qb alike.
NEW_BRANCH = re.compile(
    r"\bgit\b.*\b(?:checkout|switch)\s+(?:--?[\w-]+(?:=\S+)?\s+)*"
    r"-\w*(?:b|c)\s+[\"\']?(?P<br>[\w./-]+)")

def _note_git_init(seg, base, virgin_dirs):
    """Directories a real `git init` here will create.

    The hook runs before the command, so they are not on disk yet. Reads
    git_invocations, not the text: a message mentioning an init grants nothing.
    """
    for sub_cmd, repo in git_invocations(strip_quoted(seg)):
        if sub_cmd != "init":
            continue
        toks = tokens(strip_quoted(seg))
        positional = None
        if "init" in toks:
            # Skip flag VALUES: in `git init -b main` the directory is not
            # `main`, that is the branch name.
            takes_value = {"-b", "--initial-branch", "--template",
                           "--separate-git-dir", "--object-format", "--ref-format"}
            rest, skip = [], False
            for x in toks[toks.index("init") + 1:]:
                if skip:
                    skip = False
                    continue
                if x in takes_value:
                    skip = True
                    continue
                if x.startswith("-"):
                    continue
                rest.append(x)
            positional = rest[0] if rest else None
        where = repo or positional
        target = os.path.normpath(os.path.join(base, normalize_path(where))) \
            if where else base
        # Re-initialising an EXISTING repo with history must not mark it
        # virgin: an init followed by a commit on a real main was allowed.
        if not (is_git_repo(target) and has_commits(target)):
            virgin_dirs.add(target)

def _note_checkout(seg, here, unknown_cwd, branch_override):
    """The branch a checkout/switch leaves you on, or None if unprovable.

    Callers gate on `not prose`: an echoed checkout grants nothing.
    """
    if not any(s in ("checkout", "switch") for s, _ in git_invocations(seg)):
        return branch_override
    # Quotes REMOVED, not quoted runs deleted: a quoted branch name lost its
    # whole value to strip_quoted, so the override was dropped and the guard
    # blocked its own advice.
    unquoted = seg.replace('"', "").replace("'", "")
    nb = NEW_BRANCH.search(unquoted)
    if nb:
        return nb.group("br")
    # A checkout back to an EXISTING branch must clear the override. Leaving it
    # set meant a temporary branch kept vouching for a protected one for the
    # rest of the line. VERIFIED against git, not merely shaped like a branch
    # name: `git checkout src` names a directory, and taking it on faith
    # invented a non-protected branch that disabled the branch rule.
    cand = _checkout_target(unquoted)
    return cand if (cand and not unknown_cwd and is_branch(here, cand)) else None
