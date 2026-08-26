# Engineering Baseline

These are conservative defaults for agents changing software. Repository instructions and `AGENTS.local.md` take precedence where they are more specific.

## Safety guardrails

When the On Belay guard is installed, its PreToolUse hooks block common high-impact mistakes before execution. The written rules still apply when the hooks are absent. They are a safety net for a careless agent, not a security boundary. Do not work around a block or ask the user to disable it.

- Never commit or push on `main`, `master`, `prod`, `production`, `trunk`, or `release`. Branch and use a pull request. Merge, revert, cherry-pick, and `am` can create commits too. Abort, skip, and quit forms are safe exits. A continue form may write a commit, so check the target branch yourself before continuing an in-progress operation.
- Never force-push, use `reset --hard`, run `clean -f`, discard the whole working tree, or force-delete a branch. The one exception is `git push --force-with-lease=<branch>:<sha>` on your own open PR branch after a rebase. Use the current branch and a full pre-fetch commit SHA. It is refused on protected branches.
- Never read or write a real `.env`, private key, credential store, or token file. Use `.env.example` for names. Ask the human to set values through a channel that does not expose them to the model.
- Never connect to a production database. Never run `DROP`, `TRUNCATE`, or an unqualified or tautological `DELETE` or `UPDATE` against a database that is not proven local.
- Treat deployments, merges, releases, infrastructure changes, and external writes as material actions. Confirm authorization and scope before proceeding when the user has not already granted it.

Installed hooks fail open on internal errors and record them in `~/.claude/guard-failopen.log`. Host permissions, branch protection, least-privilege credentials, backups, and review remain stronger controls.

## Working method

Before changing code:

1. Read the request, repository instructions, relevant code, tests, and recent diff.
2. Find what already solves the problem: existing code, platform capability, standard library, or installed dependency.
3. Identify the observable behavior, invariants, risk, and verification route.
4. Make the smallest coherent change that fully solves the requested problem.

Do not create abstractions for hypothetical reuse. Put each invariant in one authoritative place. Prefer types, constraints, and narrow interfaces over repeated defensive branches. Hide implementation complexity behind stable contracts, but add a seam only where behavior actually varies or an external boundary exists.

Preserve user changes in a dirty tree. Never delete, overwrite, or reformat unrelated work. Prefer editing existing files. Delete dead code instead of commenting it out. When taking a deliberate shortcut, document what it does not handle and the concrete condition that should trigger reconsideration.

## Verification

Use test-driven development for business behavior and regressions when a meaningful red test is possible. Test through public interfaces. Mock external systems, time, or randomness, not modules the project owns.

Every behavioral change needs evidence proportionate to risk:

- run the focused test and relevant suite;
- run format, lint, typecheck, and build checks the repository defines;
- exercise changed UI, API, CLI, migration, or integration behavior through its real public path;
- inspect the final diff for unrelated files, secrets, generated output, and missing failure handling.

Never skip, weaken, or delete a failing test to obtain green. If a check cannot run, report that fact and the remaining risk.

A guard, test, or lint rule is not proven until a deliberate violation makes it fail and restoring the rule makes it pass.

## Git and delivery

Follow the repository's branch and commit conventions. Keep commits coherent and review the staged diff before committing. Every change should go through a pull request and required CI. Do not merge, deploy, publish, tag a release, or rewrite shared history without explicit authority.

Before deployment, check migration compatibility, rollout behavior, observability, and rollback. After deployment, verify the live version and user-visible behavior, not only the pipeline status.

## Skills

The user describes the work; they should not have to remember the workflow.
Use the smallest skill that matches the current stage. Do not run completed
stages again.

For every adopted repository, keep one real root `AGENTS.md` as the canonical
project contract and a relative `CLAUDE.md -> AGENTS.md` symlink. Run
`agent-init` to establish or check that shape. Never maintain independent
instructions for the two hosts.

- `navigate`: make or challenge a decision.
- `prototype`: answer one unresolved question with disposable evidence.
- `bootstrap`: create a minimal repository and delivery path.
- `setup`: adopt an existing repository's tracker, verification, CI, and release contract.
- `to-spec`: capture an already-decided acceptance contract.
- `breakdown`: slice decided work into independently shippable items.
- `domain-modeling`: establish business language, rules, states, and ownership.
- `architect`: design a module or rank evidence-backed architecture improvements.
- `tdd`: implement behavior in red, green, refactor cycles.
- `diagnose`: establish root cause with a reproducible feedback loop.
- `review`: inspect a fixed diff for correctness, requirements, security, and maintainability.
- `ship`: verify, commit, open a PR, watch CI, and perform only the delivery actions the user authorized.
- `unstick`: resolve an in-progress Git conflict without discarding intent.

Announce the chosen skill and why. Follow its handoff when the user has already authorized the next stage. Stop at approval gates for external or irreversible actions.

The optional extras (`--extras`) add `research`, `wizard`, and `handoff`. Use `research` for bounded primary-source work, `wizard` for human-only credential or dashboard steps, and `handoff` when state must cross an agent, host, directory, or long pause. Do not assume those skills are installed.

## Local overrides

If `AGENTS.local.md` exists next to this file, read it. It is the place for personal writing style, preferred tools, and environment-specific rules that should not be published with this baseline.
