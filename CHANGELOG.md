# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-08-26

### Changed

Renamed to **On Belay**. The package is now `@sid-thephysicskid/onbelay` and
the command is `onbelay`.

"On belay?" / "Belay on!" is the call-and-response climbers exchange before the
climber moves: a check spoken out loud, every time, before the next action.
That is what a PreToolUse hook is. The second meaning is the one that matters
more: a belay rope does not stop you climbing, it catches you when you fall,
which is this project's whole stance. Not a sandbox. A rope, with something on
the other end of it.

The old name described the file it wrote. This one describes what it does.

Every identifier moved with it: `~/.local/share/onbelay/` for the payload,
`onbelay-hook-v1` markers in settings.json, `onbelay:start` blocks in
instruction files, `.onbelay-origins`, `ONBELAY_COMPACT`, and
`ONBELAY_NONINTERACTIVE`. The protected-branch override is now
`ONBELAY_PROTECTED_BRANCHES`.

`@sid-thephysicskid/agent-config` is deprecated and points here. If you
installed it, run its `uninstall` before installing this: the two use
different paths and markers, and nothing is shared between them.

## [0.3.1] - 2026-08-26

Five independent audits, then the fixes. Every finding below was reproduced
against the published 0.3.0 payload before it was touched, and two of them were
found by this repo's own corpus catching a change to itself.

### Fixed

The guard did not protect its own installed files. The npm install copies the
payload to `~/.local/share/onbelay/` and leaves `~/.claude/hooks` as
symlinks into it, and only the symlink location was guarded, so
`rm -rf ~/.local/share/onbelay` removed the whole guard and was allowed.
The hook shim exits 0 when its file is missing, so the result was a machine
with no guard and nothing saying so.

`ONBELAY_PROTECTED_BRANCHES` did not reach `branch -f`, `checkout -B` or
`update-ref`, which carried a hand-typed copy of the default list. It was wrong
in both directions: a team on `develop` got no protection from those three, and
an empty value, which the README says turns the rules off, still refused moving
`main`.

Naming a config FILE switched off the production-deploy rules. `fly.toml`,
`wrangler.toml` and `serverless.yml` are the default names those tools ship
with, so the ordinary invocation was exempt, and an explicit `--prod` was
defeated by a config file sitting beside it. `--config` and `--profile` now
need a positive test, and an explicit production flag is not open to
reinterpretation.

An interpreter heredoc runs its body exactly as `-c` does, but `segments()`
splits that body one line per segment, so the inline-program rule never saw a
program and its delete half was off for every heredoc spelling.

kubectl short resource names, and one extra flag on a wrapper walking past the
interpreter-name scan.

`MIDDLE_SIGNALS` was a hand-written union missing `guard_paths`, so a write to
the guard's own files buried past the 32KB analysis cap fell straight through.
It is discovered now rather than listed.

### Fixed: refusals of ordinary work

A sweep over 1,042 safe commands measured a 2.6% over-block rate. Seven root
causes, all daily commands:

- Naming a secret file is not disclosing it. Deleting a local dotenv, opening
  one in an editor, `direnv allow`, and the `--cached` removal that is the
  standard remediation for a committed secret were all refused. `git add`
  stays refused, and so do diff, show and log -p, which print contents.
- A package runner is not the command: one `npx` defeated every exemption in
  `check_secrets_cmd` at once.
- A git config line with nothing after the key is a read, and `--unset`
  removes the hazard. Both were refused while `--list` was allowed.
- `--help` and `git help <topic>` are documentation. `check_tools` has always
  known that; `check_git` did not.
- `git rm` is a git subcommand, not coreutils `rm`.
- A trailing glob with a literal left after the metacharacters selects a
  subset, so a scoped cleanup was read as the whole directory.
- The shape every new project starts with, and the one `bootstrap` emits:
  mkdir, cd into it, git init, first commit.
- A redirect is not a refspec, so `2>&1` refused the one force-push this
  suite deliberately allows.

### Fixed: install and CLI

Upgrading over an existing install left the extras bound to the previous
payload root, neither migrated nor removed.

`doctor` checked the profile it assumed rather than the one installed, so a
guard-only machine reported 30 problems with nothing wrong, and pointed at
`./install.sh`, a file an npx user does not have. `doctor guard --extras`
silently ignored both the conflict and the flag.

### Changed

`npm test` ran 8 assertions out of 2,048; it runs the gates now. The LICENSE
appendix that stopped GitHub identifying the licence moved to the README, where
people read it. Issue templates, one per direction the guard can be wrong in.
A docs-only change no longer runs the parser suite to prove prose is prose.

### Known gaps

64 accepted, out of 104 red-team candidates, each with a written reason in
`evals/redteam-candidates.txt`. Six were added this release rather than closed,
including two write-then-run spellings where two functions answer one question
and disagree.

## [0.3.0] - 2026-08-21

Bugs, and a repository 39% smaller: 29,367 tracked lines to 17831, 236 files
to 108. No guard rule and no test case was removed, and the rule corpus grew
from 1,244 cases to 1,593.

### Fixed

Verification that claimed more than it established:

- `doctor` and `--check` prove the guard still decides, instead of only proving
  it is wired. A rule module that no longer imports leaves every symlink and
  settings entry intact, so the check reported "Guard active" on a machine that
  would have accepted a force push. One probe per rule module, so a single dead
  module is named rather than masked by a neighbour that still answers.
- `doctor` and `--check` surface a non-empty `~/.claude/guard-failopen.log`. The
  guard had recorded every fail-open since it was written and nothing read it.
- The workflow banner counts what is linked instead of printing `13/13`. A
  same-name skill you already had is kept by design, and the banner claimed
  ours was active anyway.
- The skills evaluator fails when its fixtures cannot be built, instead of
  warning and exiting 0, and its summary reports what ran rather than what it
  would have run.
- An argv-shaped tool call reached a different verdict than the same command
  as a string. 66 of the suite's cases disagreed, every one blocking as a
  string and passing as argv, including an inline program deleting a system
  path. The suite now asserts the two agree on every case.
- Five git rules and two filesystem rules stopped applying once a command was
  padded past the analysis window, which the rule that owns that list says
  must never happen.
- The guard's own test fixtures inherited the developer's `~/.gitconfig`. With
  `commit.gpgsign` set, the fixture commits never happen and the suite fails
  for reasons unrelated to the change under test.
- Two of five git-state caches stored the answer given when the subprocess
  budget was spent, freezing it for the rest of the process.

Guardrails that refused ordinary work:

- A command substitution written inside single quotes is text. Documenting a
  dangerous command was treated as running it.
- A commit message is prose in every spelling, not only `-m`.
- A git dry run is a preview. `clean` with both a dry-run and a force flag
  deletes nothing, and a dry-run push sends nothing.
- A piped bulk delete is judged on where the pipeline is rooted, the same way
  the `-delete` spelling already was.
- A CA bundle named as the trust store to verify with is public by role,
  whatever the file is called.
- Control paths are protected by location, not by filename shape, so a
  throwaway fixture and a second profile are no longer refused.

Guardrails that missed:

- An in-place edit is a write. The unmake list named rm, mv, cp, tee, chmod and
  ln, so the guard could not protect its own configuration from the one verb an
  agent is most likely to reach for when editing a file from a shell.
- Credentials an agent meets inside a container. The credential directory list
  was the dot-directories in a home, so the Docker and Compose secrets mount
  and the Kubernetes service-account token were all readable.
- A client certificate's private half. The flag naming the certificate blocked;
  the flag naming the key did not.
- A script written under a bare name and run with a leading `./` did not join
  up as write-then-run, while the same two segments with matching spellings did.
- A bulk delete of every untracked file, which is the forced clean this guard
  refuses, reached by a different spelling.
- A dry-run flag counted from anywhere in the line, including inside a pathspec
  after `--`, so a forced clean could read as a preview and delete.
- A flag between a wrapper and the binary no longer disables rules anchored on
  the head of the command. Eleven shapes went through, including production
  database connections and inline programs deleting system paths.
- The credential gate detects current issuer formats. It matched an AWS key id
  and never the secret.

Installer:

- The global instructions the installer links carried the skill routing and
  none of the safety rules, so every install produced hooks that block with no
  written policy behind them, and the rules that still apply when the hooks are
  absent were absent too. check-docs now pins the section to AGENTS.md.

- Instruction files get a recovery copy before the first edit, and keep their
  line endings. Text between pre-existing markers was destroyed with nothing to
  restore from.
- A dangling Codex `hooks.json` symlink aborts before anything is wired,
  instead of after the whole Claude half.
- A recovery copy is never taken of a file this installer created, so it cannot
  hand back its own writes as the "before" state.
- Uninstall says which deny rules it left behind when the ownership record is
  missing, instead of leaving them silently.

### Added

- `docs/guard-coverage.md`, generated from the rules, with the threat model and
  the accepted gaps. `SECURITY.md` defines a reportable bypass against it.
- `scripts/gates`, one list of every gate, with `--hermetic` to run them
  with nothing inherited from the developer's machine. It replaces two
  drivers that kept two hand-maintained copies of the list and had already
  drifted apart.

### Changed

- Documented the guard-only install, which shipped and was never mentioned.
- Removed the plugin marketplace and the `plugins/` tree: 6,390 lines that
  were 98% a byte-identical copy of `hooks/` and `skills/`, kept in sync by
  hand and policed by six tests, serving an install path that was never
  documented. `npx ... install guard` is the guard-only path.
- Stated the Python and Node floors that are actually tested.
- Removed the compliance experiment: 4,486 lines with no coupling to the
  product, whose one published result was withdrawn and whose confirmatory run
  was never executed. `evals/README.md` records what was withdrawn and why.
- Merged `hooks/floor.py` into `hooks/cases.py`. Its cases were written against
  the job rather than the rules and that method stays, under a THE FLOOR
  banner; a coverage measurement showed the second file and its second runner
  reached no line the first did not.
- Cut six skill checks that had never produced an error, with the six test
  classes and three scorecard columns that served them. The four that remain
  can all fail.
- One cached, budgeted git question in `hooks/guard_repo.py` instead of five
  copies of it. One key-walker in the Codex adapter instead of two. One
  fixture builder for the evals instead of a second one that scrubbed the
  environment differently.
- The accepted-gap corpus explains each decision once and cites it by tag,
  instead of pasting the same paragraph up to twelve times.

## [0.2.0] - 2026-08-13

### Changed

- Made one install command add guardrails, workflow skills, and automatic routing.
- Added optional extras through `--extras` instead of requiring profile selection.
- Preserved and extended existing agent instructions through a removable managed block.
- Added reversible handling for same-name skills, custom agent homes, and dotfile-managed paths.

## [0.1.1] - 2026-08-12

### Changed

- Reduced the README to purpose, installation, behavior, and verification.
- Replaced decorative graphics with one system diagram.
- Kept third-party attribution concise and license-focused.

## [0.1.0] - 2026-08-12

### Added

- Deterministic pre-tool guardrails for Claude Code and Codex, with explicit
  limits and tested safe alternatives.
- Independent `guard`, `workflow`, `operator`, and `full` install profiles.
- Thirteen delivery skills, plus optional research, credential setup, handoff,
  and communication preferences.
- Shared global instructions and a project initializer that keeps `AGENTS.md`
  canonical and links `CLAUDE.md` to it.
- `npx`, clone-based, and native plugin packaging with selective uninstall.
- Local and CI checks for guard behavior, installers, packages, skills,
  provenance, and documentation.
