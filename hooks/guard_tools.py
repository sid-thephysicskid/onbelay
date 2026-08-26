#!/usr/bin/env python3
"""Filesystem and CLI destruction: rm, and the tool table."""
import os
import re
import shlex

from guard_parse import (  # noqa: F401
    asks_for_help,
    GLOBBED,
    _brace_fragments,
    _is_dot_walk,
    brace_expand,
    inline_code,
    normalize_path,
    tokens,
)
from guard_secrets import (
    is_secret_candidate,
)
from guard_git import (
    _is_whole_tree,
)

# See guard_git.MIDDLE_SIGNALS for why these live next to the rules.
MIDDLE_SIGNALS = (
    r"\brm\s+-[\w-]*[rRf]",
    r"\bmkfs(\.\w+)?\b",
    # `rm -rf` was here and the find spelling of the same act was not.
    r"\bfind\b[^\n]{0,120}\s-delete\b",
    r"\bfind\b[^\n]{0,120}-exec(?:dir)?\s+(?:\S*/)?rm\b",
    r"\bdd\b[^\n]{0,120}\bof=/dev/",
    r"\b(terraform|tofu|terragrunt)\b[^\n]{0,40}\bdestroy\b",
    r"\bkubectl\b[^\n]{0,60}\bdelete\b",
    r"\bgh\b[^\n]{0,40}\brepo\s+delete\b",
    r"\bgh\b[^\n]{0,60}-X\s+DELETE\b",
    r"\bgh\b[^\n]{0,60}\bpr\s+merge\b[^\n]{0,40}--admin\b",
    r"\bvercel\b[^\n]{0,30}\b(rm|remove)\b",
    r"\baws\b[^\n]{0,40}\bs3\s+r[mb]\b",
    r"\b(npm|pnpm|yarn|cargo)\b[^\n]{0,40}\bpublish\b",
    r"\btwine\b[^\n]{0,40}\bupload\b",
    r"\bgem\b[^\n]{0,40}\bpush\b",
    r"\bpoetry\b[^\n]{0,40}\bpublish\b",
    # Production deploys, same list as PRODUCTION_DEPLOYS below. A rule that
    # stops applying at 40KB is the defect this file already carries a test for.
    r"\b(vercel|netlify)\b[^\n]{0,80}--prod(uction)?\b",
    r"\b(fly|flyctl|modal|sst|serverless|sls|eb)\b[^\n]{0,40}\bdeploy\b",
    r"\bwrangler\b[^\n]{0,40}\b(deploy|publish)\b",
    r"\brailway\b[^\n]{0,40}\b(up|redeploy)\b",
    r"\blambda\s+update-function-code\b",
    r"\bmigrate\s+deploy\b",
)

_HOME = os.path.expanduser("~")

DANGEROUS_ROOTS = {"/", _HOME, os.path.dirname(_HOME), "/Users", "/home",
                   "/etc", "/var", "/usr", "/System", "/Applications"}

def _under_system_root(base):
    """The four shapes that make a delete root dangerous.

    Factored because check_rm's `find` branch had only the first two, so
    `find /Users/someone -delete` and `find . -name .git -exec rm -rf {} +`
    were allowed while the `rm -rf` spellings of both were blocked.
    """
    return (base in DANGEROUS_ROOTS
            or (base.startswith("/") and base.count("/") <= 1)
            or bool(re.match(r"^/(private|Library|System|usr|var|etc|opt)/[^/]+/?$", base))
            or bool(re.match(r"^/(Users|home)/[^/]+/?$", base)))

def check_rm(seg):
    if re.search(r"\bfind\b.*(\s-delete\b|-exec(dir)?\s+(\S*/)?rm\b)", seg):
        # Only dangerous when rooted somewhere dangerous. `find . -name '*.pyc'
        # -delete` is a daily command and blocking it gets the guard switched off.
        mm = re.search(r"\bfind\s+(?P<root>'[^']+'|\"[^\"]+\"|\S+)", seg)
        root = normalize_path(mm.group("root")) if mm else ""
        if _under_system_root(root):
            return ("a find that deletes files in bulk under a system path.",
                    "narrow the search root, or list the matches first without -delete")
        # `find . -name .git -exec rm -rf {} +` is the standard recipe for
        # stripping history from a tree, and it destroys every repository under
        # it. The rm spelling is blocked; this one was not.
        if re.search(r"-name\s+['\"]?\.git['\"]?(\s|$)", seg) or root.endswith("/.git"):
            return ("a find that deletes .git directories (destroys the repositories).",
                    "if you meant to discard a clone, delete its parent directory instead")
    toks = tokens(seg)
    # `git rm` is a git SUBCOMMAND, not coreutils rm. It removes paths from the
    # index, and `git rm -r --cached .` deletes nothing from disk at all: it is
    # the standard recipe for re-applying .gitignore. Matching any token whose
    # basename is `rm` reported "rm -rf on the whole current directory" for a
    # command that touches no file. Segments are already split on `;`, `&&` and
    # `|`, so a `git` anywhere before the `rm` in THIS segment is that git.
    def _coreutils_rm(i):
        return os.path.basename(toks[i]) == "rm" and not any(
            os.path.basename(t) == "git" for t in toks[:i])
    rm_at = [i for i in range(len(toks)) if _coreutils_rm(i)]
    if not rm_at:
        return None
    idx = rm_at[0]
    flags = "".join(t for t in toks[idx + 1:] if t.startswith("-"))
    if not re.search(r"[rRf]", flags):
        return None
    for t in toks[idx + 1:]:
        if t.startswith("-"):
            continue
        # A bare `*` or `..` never survives normalize_path into something
        # DANGEROUS_ROOTS would recognise, so ask the pathspec helper first.
        # Every brace member gets the full check, not just a whole-token
        # brace list against one predicate. `rm -rf ~/{,.config}` expands to
        # `~/` and `~/.config`, and only the first was ever looked at.
        for member in (brace_expand(t) if "{" in t else [t]):
            if "{" in member or "}" in member:
                # Past the expansion budget. See is_secret_candidate: the
                # concatenated form matches nothing, so judge each fragment.
                for frag in (f for f in _brace_fragments(member)
                             if len(f) < len(member) and "{" not in f and "}" not in f):
                    hit = _rm_target_verdict(frag)
                    if hit:
                        return hit
                continue
            hit = _rm_target_verdict(member)
            if hit:
                return hit
    return None

def check_xargs_rm(cmd):
    """A bulk delete driven by the previous stage of a pipeline.

    A WHOLE-LINE rule on purpose. Segments split on `|`, so the consumer never
    sees the producer that decides whether the delete is dangerous, and judging
    the consumer alone cannot see a system root at all.

    Same test as the find branch, so the two spellings of one act agree.
    Refusing this unconditionally meant the piped spelling of the daily
    `*.pyc` cleanup was blocked while the `-delete` spelling of the identical
    command was allowed. A guard that refuses the daily cleanup gets switched
    off, which costs more than this rule ever bought.

    Command position, not anywhere in the line: the tool name also matched a
    FILENAME, so deleting a directory whose name merely contained it was
    refused as if the tool were driving the delete.
    """
    if not re.search(r"(^|\|)\s*(xargs|parallel)\b", cmd):
        return None
    if not re.search(r"\brm\b", cmd):
        return None
    # No pipeline producer means the list arrives from a redirect or a file, so
    # its contents are unknowable and there is nothing to judge but the act.
    # Fail closed there, which is what the earlier unconditional rule got right.
    if not re.search(r"\|\s*(xargs|parallel)\b", cmd):
        return ("a bulk delete by xargs/parallel, fed from input the guard cannot see.",
                "read the list and delete the specific paths you meant")
    # normalize_path on EVERY token, not only the ones already absolute: `~`
    # and `$HOME` name a home directory without a leading slash, and a producer
    # of `echo ~` is exactly as dangerous as one of `echo /Users/someone`.
    if any(_under_system_root(normalize_path(t)) for t in tokens(cmd)):
        return ("a bulk delete driven by xargs/parallel under a system path.",
                "narrow the producer, or list the matches first")
    # A producer that ENUMERATES UNTRACKED FILES is as dangerous as a system
    # root, and the paths it emits are relative so the root test cannot see it.
    # `git ls-files --others | xargs rm -f` is byte-for-byte the effect of
    # `git clean -f`, which is refused and which docs/guard-coverage.md lists as
    # deleting untracked files permanently. Untracked files have no recovery
    # path, so one rule refusing the act while another permits its synonym is
    # the worst kind of inconsistency to leave in.
    # `-o` is the short spelling of --others, and it appears in clusters.
    if re.search(r"\bgit\b[^|]{0,60}\bls-files\b[^|]{0,60}"
                 r"(--others|(?<![\w-])-[a-zA-Z]*o[a-zA-Z]*(?=\s|$))", cmd):
        return ("a bulk delete of every untracked file, which is git clean -f "
                "by another name.",
                "delete the specific paths you meant, or use git clean -n first "
                "to see what would go")
    return None


def _glob_means_everything(comp):
    """Does this path component match every entry in its directory?

    `*`, `.*`, `.??*` and `.[a-z]*` do. `*.log` and `build*` do not: they leave
    a literal behind once the metacharacters are gone, so they select a subset
    and the parent directory is not what is being deleted.
    """
    bare = re.sub(r"\[[^\]]*\]", "", comp).replace("*", "").replace("?", "")
    return bare in ("", ".")


def _rm_target_verdict(t):
    """Judge ONE expanded rm operand."""
    if _is_whole_tree(t) or _is_dot_walk(t):
        return ("rm -rf on the whole current directory (or its parent).",
                "name the specific subdirectory you mean, with its path")
    p = normalize_path(t)
    # Strip a trailing glob COMPONENT, not just the literal `/*`:
    # `~/.*`, `~/.[a-z]*` and `~/.??*` all mean "everything in home".
    #
    # ...but ONLY when the component really does mean everything. Stripping any
    # globbed component collapsed `rm -rf ./*.log` to `.` and refused it as
    # "the whole current directory", while the identical `rm -rf *.log` with no
    # `./` was allowed: the same command, judged two ways, and the spelling
    # people use in a Makefile was the one that lost. A component with a
    # literal part left after the metacharacters selects a subset, so the
    # operand is the glob itself, not its parent.
    base = p
    if GLOBBED.search(p):
        mm = re.search(r"/([^/]*[*?\[][^/]*)/?$", p)
        if mm and _glob_means_everything(mm.group(1)):
            base = re.sub(r"/[^/]*[*?\[][^/]*/?$", "", p)
    base = normalize_path(base) if base != p else p
    if base in ("", "."):
        # Also the only thing catching `rm -rf /*`: the glob strip leaves an
        # empty base, and neither _is_whole_tree nor _is_dot_walk sees that
        # shape. Keep the clause and keep the test that pins it.
        return ("rm -rf on the whole current directory (or the filesystem root).",
                "name the specific subdirectory you mean, with its path")
    # One level below a system root is still the system, and anything under
    # /Users or /home is somebody's whole account. Shared with the `find`
    # branch above, which used to have only half of these.
    if _under_system_root(base):
        return (f"rm -rf on '{t}', a home or system directory.",
                "delete a specific subdirectory, with the full path")
    if base == ".git" or base.endswith("/.git"):
        return ("rm -rf on a .git directory (destroys the repository).",
                "if you meant to discard a whole clone, delete its parent directory instead")
    return None

# Global flags that sit between the binary and its verb. Every pattern below
# used to demand adjacency, so `kubectl -n prod delete namespace staging` and
# `terraform -chdir=./infra destroy` walked straight through the rules README
# the README promises by name.
# Bounded on purpose. The first draft was `(?:...)*` around an alternation
# whose branches could match the same text, which backtracks exponentially and
# hung the suite. A repetition cap keeps the worst case constant, and nobody
# passes nine global flags before the verb.
_GLOBAL_FLAGS = r"(?:\s+-{1,2}[\w-]+(?:[=\s]+[^\s-]\S*)?){0,8}"

DESTRUCTIVE_TOOLS = (
    # Formatting a filesystem, and writing to a raw device node. Neither is
    # part of shipping a web app, both are unrecoverable, and `of=` is what
    # separates them from ordinary use: `dd of=testfile` writes a file and is
    # allowed, `dd of=/dev/sda` overwrites the disk.
    (r"\bmkfs(\.\w+)?\b", "mkfs (formats a filesystem, destroying its contents)",
     "do this yourself, on a device you have named out loud"),
    (r"\bdd\b[^\n]{0,120}\bof=/dev/", "dd writing to a raw device node",
     "write to a file instead, or do this yourself"),
    (r"\bgh" + _GLOBAL_FLAGS + r"\s+repo\s+delete\b", "deleting a GitHub repository",
     "do this in the web UI, deliberately"),
    (r"\bgh" + _GLOBAL_FLAGS + r"\s+api\b.*(-X|--method)[=\s]+DELETE\b",
     "a DELETE against the GitHub API", "do this in the web UI, deliberately"),
    (r"\bgh" + _GLOBAL_FLAGS + r"\s+pr\s+merge\b.*--admin\b",
     "merging a PR with --admin (bypasses required checks)",
     "let CI pass, or ask the human to override"),
    (r"\b(terraform|tofu|terragrunt)" + _GLOBAL_FLAGS + r"(\s+run-all)?" +
     _GLOBAL_FLAGS + r"\s+destroy\b",
     "terraform destroy (tears down infrastructure)",
     "run terraform plan -destroy and show it first"),
    (r"\b(terraform|tofu|terragrunt)" + _GLOBAL_FLAGS + r"(\s+run-all)?" +
     _GLOBAL_FLAGS + r"\s+apply\b.*\s-destroy\b",
     "terraform apply -destroy (tears down infrastructure)",
     "run terraform plan -destroy and show it first"),
    # `--dry-run=client|server` really is a no-op for kubectl. `--dry-run=none`
    # is NOT: it is the default and it deletes.
    (r"\bkubectl" + _GLOBAL_FLAGS + r"\s+delete" + _GLOBAL_FLAGS +
     r"\s+(namespaces?|ns|deployments?|statefulsets?|pvcs?)\b"
     r"(?![^\n]*--dry-run=(client|server)\b)",
     "deleting a Kubernetes resource",
     "scale to zero first, or do it deliberately outside the agent"),
    # aws spells it `--dryrun`, one word.
    (r"\baws" + _GLOBAL_FLAGS + r"\s+s3\s+rm\b(?![^\n]*--dry-?run\b).*--recursive",
     "recursive S3 deletion", "list the keys first, then delete specific ones"),
    (r"\baws" + _GLOBAL_FLAGS + r"\s+s3\s+rb\b(.*--force|.*--recursive)",
     "removing an S3 bucket and its contents", "empty it deliberately outside the agent"),
    (r"\bvercel" + _GLOBAL_FLAGS + r"\s+(rm|remove)\b",
     "removing a Vercel deployment or project", "do this in the dashboard, deliberately"),
    (r"\bdropdb\b", "dropdb", "write a forward migration instead"),
    # Publishing to a public registry cannot be undone: npm unpublish is
    # restricted to 72 hours and a narrow set of conditions, crates.io and
    # PyPI never let you reuse a version at all. /ship says the agent must not
    # do this unasked, and the guard is what makes that stick.
    (r"\b(npm|pnpm|bun)" + _GLOBAL_FLAGS + r"\s+publish\b(?![^\n]*--dry-run(?![-\w=]))",
     "publishing to the npm registry (irreversible)",
     "let the tag-triggered CI workflow publish, or ask the human to run it"),
    (r"\byarn" + _GLOBAL_FLAGS + r"\s+(npm\s+)?publish\b(?![^\n]*--dry-run(?![-\w=]))",
     "publishing to the npm registry via yarn (irreversible)",
     "let the tag-triggered CI workflow publish, or ask the human to run it"),
    (r"\bcargo" + _GLOBAL_FLAGS + r"\s+publish\b(?![^\n]*--dry-run(?![-\w=]))",
     "publishing to crates.io (irreversible: a version can never be reused)",
     "let the tag-triggered CI workflow publish, or ask the human to run it"),
    (r"\b(twine\s+upload|gem\s+push|poetry" + _GLOBAL_FLAGS + r"\s+publish)\b"
     r"(?![^\n]*--dry-run(?![-\w=]))",
     "publishing to a package registry (irreversible)",
     "let the tag-triggered CI workflow publish, or ask the human to run it"),
)

# Destructive calls inside `python3 -c` / `perl -e`. Deliberately short: an
# inline program is not a command line, and the shell rules applied to one read
# `console.log('delete from queue')` as an unqualified DELETE.
INLINE_DESTRUCTIVE = re.compile(
    r"\b(shutil\s*\.\s*rmtree|os\s*\.\s*(remove|unlink|rmdir)"
    r"|Path\s*\([^)]*\)\s*\.\s*unlink|unlink\s+glob|File\s*\.\s*delete"
    # Node's fs, which the list did not know: `require('fs').rmSync('/etc',
    # {recursive:true})` is the JavaScript spelling of `rm -rf`. Matched on the
    # method name alone, because the module name sits inside quotes in the
    # `require('fs')` form and never touches the dot.
    r"|rmSync|rmdirSync|unlinkSync"
    r"|FileUtils\s*\.\s*rm_rf|Dir\s*\.\s*rmdir)", re.I)


def check_inline_code(seg):
    """Destructive or secret-reading calls inside an inline program.

    Two questions only: does it delete something at a dangerous root, and does
    it open a live credential. Anything wider produces false positives on
    ordinary scripting, which is the whole reason this is not check_command.
    """
    code = inline_code(seg)
    if not code:
        return None
    literals = re.findall(r"['\"]([^'\"]{1,300})['\"]", code)
    if INLINE_DESTRUCTIVE.search(code):
        for lit in literals:
            t = normalize_path(lit)
            # `unlink glob "~/*"` names the home directory with a trailing
            # glob, so the exact-match test missed it. Judge the stem too.
            stem = re.sub(r"/?\*+$", "", t) or t
            # Ask the SAME question `rm -rf <path>` would be asked, rather than
            # keeping a second, narrower notion of a dangerous root here. The
            # two had already diverged: `rm -rf /etc/nginx` was blocked and
            # `fs.rmSync('/etc/nginx')` was not, which is the same act in a
            # different language.
            if _is_dot_walk(lit) or _under_system_root(t) or _under_system_root(stem) \
                    or check_rm("rm -rf " + shlex.quote(lit)):
                return ("an inline program deleting a system or home directory.",
                        "name the specific subdirectory, and run it as a script you can read")
    for lit in literals:
        if is_secret_candidate(lit):
            return (f"an inline program reading '{lit}', which holds live secrets.",
                    "use the .example variant; never read or print the real values")
    return None


# Deploying AROUND the pipeline. Not "no deploying": merging a PR is a deploy
# too, and that one goes through CI, review and branch protection. This is the
# one that goes straight from a laptop to users. The alternative is always the
# same, so it is the same fix line, and the escape hatch is that a human types
# the command themselves.
#
# Preview and draft deploys stay allowed on purpose. They are what an agent
# SHOULD be doing, they are most of the daily traffic on these tools, and a
# guard that eats them is one people switch off.
#
# Two shapes, and conflating them leaves half the list open. Some tools ship a
# preview unless you pass a production flag. Others ship to production BY
# DEFAULT and have no such flag, so the bare invocation is already the
# dangerous one. Requiring a flag everywhere would have missed fly, wrangler,
# railway, modal and eb entirely.
_DEPLOY_FIX = ("merge the PR and let the pipeline deploy, or run this yourself")

# `--prod` on these two means "the production deployment", which a read-only
# subcommand is perfectly entitled to ask about. `vercel logs my-app --prod`
# reads logs and changes nothing, and the floor suite caught it being blocked.
# Naming the readers is narrower than trying to name every deploy spelling.
_READ_ONLY_SUB = (r"(?![^\n]{0,40}\b(logs?|ls|list|inspect|env|whoami|domains|"
                  r"certs|alias|link|pull|build|status|open|sites|dev)\b)")

PRODUCTION_DEPLOYS = (
    # Needs a production flag; without it these deploy a preview.
    (r"\bvercel\b" + _READ_ONLY_SUB + r"[^\n]{0,80}--prod(uction)?\b",
     "a Vercel production deploy"),
    (r"\bnetlify\b" + _READ_ONLY_SUB + r"[^\n]{0,80}--prod(uction)?\b",
     "a Netlify production deploy"),
    # Ships to production by default. The bare verb is the dangerous one.
    (r"\b(fly|flyctl)" + _GLOBAL_FLAGS + r"\s+deploy\b", "a Fly.io deploy (production by default)"),
    (r"\bwrangler" + _GLOBAL_FLAGS + r"\s+(deploy|publish)\b",
     "a Cloudflare Workers deploy (production by default)"),
    (r"\brailway" + _GLOBAL_FLAGS + r"\s+(up|redeploy)\b", "a Railway deploy (production by default)"),
    (r"\bmodal" + _GLOBAL_FLAGS + r"\s+deploy\b", "a Modal deploy (production by default)"),
    (r"\b(sst|serverless|sls)" + _GLOBAL_FLAGS + r"\s+deploy\b",
     "a Serverless deploy (production by default)"),
    (r"(^|[\s;&|(])eb" + _GLOBAL_FLAGS + r"\s+deploy\b",
     "an Elastic Beanstalk deploy (production by default)"),
    (r"\baws\b[^\n]{0,60}\blambda\s+update-function-code\b",
     "publishing new Lambda code straight to the live function"),
    # Not a deploy of code, but the same act: it applies pending migrations to
    # whatever database the environment points at, which in CI is production.
    # `migrate dev` is the local one and stays allowed.
    (r"\bprisma\b[^\n]{0,40}\bmigrate\s+deploy\b",
     "applying migrations to a live database"),
)


# `--env staging`, `--stage dev`, `--config staging.toml`. These tools deploy
# to production BY DEFAULT, which is why they are refused unqualified, but the
# flag that says otherwise was ignored, so the safe spelling was refused
# alongside the dangerous one. Anything naming prod/production/live is not
# exempt, so `--env production` still blocks.
NON_PRODUCTION = re.compile(
    r"--(env|environment|stage|config|profile)[=\s]+(?!\S*(prod|production|live))\S+",
    re.I)


def check_deploy(seg):
    if NON_PRODUCTION.search(seg):
        return None
    for pat, what in PRODUCTION_DEPLOYS:
        if re.search(pat, seg, re.I):
            return (what + ", which skips CI, review and branch protection.", _DEPLOY_FIX)
    return None


# `--help` prints usage and does nothing else. Reading the usage of a dangerous
# command is how you learn to use it safely, and refusing that teaches the agent
# the tool is untouchable rather than that the ACT is. Long form only: `-h` is
# the host flag for every database client.


def check_tools(seg):
    if asks_for_help(seg):
        return None
    hit = check_deploy(seg)
    if hit:
        return hit
    for pat, what, fix in DESTRUCTIVE_TOOLS:
        if re.search(pat, seg, re.I):
            return (what, fix)
    return None
