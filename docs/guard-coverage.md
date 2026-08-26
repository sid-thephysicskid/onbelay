# Guard coverage

## Who this is defending against

A careless agent, not an adversary. The guard reads one tool call at a time and
decides from the text of that call, immediately before it runs.

It is **not a security boundary**. It fails open on internal errors and on
analysis timeouts, a determined human or model can work around it, and it can
only see commands that arrive as tool calls. Deliberate obfuscation is out of
scope by design: encoding a command, hiding the verb in a variable, or handing
it to a remote host are all accepted gaps rather than defects. They are
enumerated with reasons in [`evals/redteam-candidates.txt`](../evals/redteam-candidates.txt).

What it is for is the mistake an agent makes while trying to help: committing to
a protected branch, force-pushing over someone's work, deleting the wrong tree,
reading a real credential, wiping a database it thought was local.

Keep branch protection, least-privilege credentials, database roles, backups,
CI, and human review. Those are the controls. This is a seatbelt.

## Matched by pattern rather than by table

These are too shape-dependent to enumerate, so they name the module that owns
them instead of pretending to a completeness they cannot have.

| Category | Owner |
|---|---|
| Commits and pushes on a protected branch, by any verb that writes history | `hooks/guard_git.py` |
| Force pushes, including the leading-plus refspec and an unpinned lease | `hooks/guard_git.py` |
| Discarding the working tree: reset, clean, checkout, restore, stash drop | `hooks/guard_git.py` |
| Reading, copying, printing or uploading a real credential or key | `hooks/guard_secrets.py` |
| Writing to a file that grants control: hooks, settings, git plumbing | `hooks/guard_paths.py` |
| Connecting to a host that looks like production | `hooks/guard_db.py` |
| Unqualified or tautological DELETE and UPDATE, DROP and TRUNCATE | `hooks/guard_db.py` |
| A program passed inline to an interpreter that deletes or reads secrets | `hooks/guard_rules.py` |

## How well it holds

`hooks/tests.py` runs every case in both the string and argv forms a host can
deliver. Its corpus has two halves: cases written against the rules, and a
block written against the JOB, chosen by asking what incident a rule is for
without looking at the implementation.

An accepted gap is not a defect. It is a shape someone tried, decided was out of
scope, and wrote down, so the next person does not have to rediscover the
argument. Read them before reporting a bypass.

<!-- BEGIN GENERATED: scripts/guard-coverage -->

## What is refused

### Git

- defining a git alias (an alias runs a different command than the one written)
- deleting a ref directly
- dropping stashed work
- force-removing a worktree with live changes
- git branch -D (force-deletes an unmerged branch)
- git branch -f on a protected branch (moves it under everyone else)
- git checkout -B on a protected branch (resets it to wherever you are)
- git clean -f (deletes untracked files permanently)
- git push --mirror (force-updates every ref and deletes remote branches)
- git reset --hard (discards committed and staged work)
- history rewrite
- moving a protected branch ref directly
- reflog expiry (destroys the recovery net)
- repointing HEAD by hand (the next commit lands on a branch you did not check out)
- repointing git's hooks directory (every later git command runs code from there)

### Filesystem and tooling

- a DELETE against the GitHub API
- dd writing to a raw device node
- deleting a GitHub repository
- deleting a Kubernetes resource
- dropdb
- merging a PR with --admin (bypasses required checks)
- mkfs (formats a filesystem, destroying its contents)
- publishing to a package registry (irreversible)
- publishing to crates.io (irreversible: a version can never be reused)
- publishing to the npm registry (irreversible)
- publishing to the npm registry via yarn (irreversible)
- recursive S3 deletion
- removing a Vercel deployment or project
- removing an S3 bucket and its contents
- terraform apply -destroy (tears down infrastructure)
- terraform destroy (tears down infrastructure)

### Production deploys and publishes

- a Cloudflare Workers deploy (production by default)
- a Fly.io deploy (production by default)
- a Modal deploy (production by default)
- a Netlify production deploy
- a Railway deploy (production by default)
- a Serverless deploy (production by default)
- a Vercel production deploy
- an Elastic Beanstalk deploy (production by default)
- applying migrations to a live database
- publishing new Lambda code straight to the live function

### Database destruction

- MongoDB collection drop
- MongoDB delete with an empty filter: removes every document
- MongoDB dropDatabase: destroys the entire database
- artisan migrate:fresh/db:wipe: drops every table
- rails db:drop/db:reset: drops the database
- redis FLUSHALL/FLUSHDB: wipes the entire keyspace

## Measured

| Measure | Count |
|---|---|
| Commands refused | 903 |
| Ordinary commands allowed | 745 |
| Path cases | 32 |
| Red-team candidates leaking untriaged | 0, or CI fails |
<!-- END GENERATED -->
