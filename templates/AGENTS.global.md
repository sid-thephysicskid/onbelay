# On Belay

## Safety guardrails

When Agent Guard is installed, its PreToolUse hooks block common high-impact mistakes before execution. The written rules still apply when the hooks are absent. They are a safety net for a careless agent, not a security boundary. Do not work around a block or ask the user to disable it.

- Never commit or push on `main`, `master`, `prod`, `production`, `trunk`, or `release`. Branch and use a pull request. Merge, revert, cherry-pick, and `am` can create commits too. Abort, skip, and quit forms are safe exits. A continue form may write a commit, so check the target branch yourself before continuing an in-progress operation.
- Never force-push, use `reset --hard`, run `clean -f`, discard the whole working tree, or force-delete a branch. The one exception is `git push --force-with-lease=<branch>:<sha>` on your own open PR branch after a rebase. Use the current branch and a full pre-fetch commit SHA. It is refused on protected branches.
- Never read or write a real `.env`, private key, credential store, or token file. Use `.env.example` for names. Ask the human to set values through a channel that does not expose them to the model.
- Never connect to a production database. Never run `DROP`, `TRUNCATE`, or an unqualified or tautological `DELETE` or `UPDATE` against a database that is not proven local.
- Treat deployments, merges, releases, infrastructure changes, and external writes as material actions. Confirm authorization and scope before proceeding when the user has not already granted it.

Installed hooks fail open on internal errors and record them in `~/.claude/guard-failopen.log`. Host permissions, branch protection, least-privilege credentials, backups, and review remain stronger controls.

## Choosing a skill

Use the smallest installed workflow skill that matches the current stage. The
user describes the outcome; they should not have to name a skill.

- Unclear direction or a plan to challenge: `navigate`.
- One unresolved question needing evidence: `prototype`.
- New repository: `bootstrap`. Existing repository with unclear setup: `setup`.
- Decided behavior needing a contract: `to-spec`, then `breakdown` if work must be sliced.
- Unclear business rules or ownership: `domain-modeling`.
- A module boundary or migration: `architect`.
- New behavior or a regression: `tdd`. Unknown failure: `diagnose`.
- Finished changes: `review`, then `ship` when delivery is authorized.
- Git conflict: `unstick`.

Enter at the current stage. Do not replay completed stages or force every task
through the whole sequence. Prefer these workflow skills over overlapping
skills unless the user explicitly names another one. Announce the skill you
use and follow its handoff when the next step is already authorized.

For an adopted repository, keep one real root `AGENTS.md` and a relative
`CLAUDE.md -> AGENTS.md` symlink. `bootstrap` and `setup` establish this. Stop
at approval gates for external, destructive, deployment, merge, or release
actions the user did not authorize.
