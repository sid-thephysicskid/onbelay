#!/usr/bin/env python3
"""The npm CLI installs from an ephemeral package into a stable home."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "bin", "onbelay.js")
# From the file that owns it. This was written out five times, so a
# release meant five edits and a red suite until all five were found.
VERSION = open(os.path.join(ROOT, "VERSION")).read().strip()


def packed(stdout):
    """The one package `npm pack --json` describes, whatever shape it used.

    npm 10 returns a LIST of packed packages; npm 11 returns an object keyed by
    name. Indexing [0] worked until the runner's npm moved, and then a release
    failed on a test about tarball contents rather than on anything real.
    """
    data = json.loads(stdout)
    if isinstance(data, dict):
        data = list(data.values())
    return data[0]


class NpxCliTest(unittest.TestCase):
    def run_cli(self, home, *args, cwd=None, check=True):
        env = dict(os.environ, HOME=home, PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run(
            ["node", CLI, *args],
            cwd=cwd or ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=check,
        )

    def test_help_and_version(self):
        with tempfile.TemporaryDirectory() as home:
            help_text = self.run_cli(home, "--help").stdout
            self.assertIn("install [guard] [--extras]", help_text)
            # The guardrails install on their own. Pinned because that path was
            # shipped, called legacy in the usage text, and documented nowhere.
            self.assertIn("install guard", help_text)
            self.assertEqual(self.run_cli(home, "--version").stdout.strip(), VERSION)

    def test_guard_round_trip_uses_stable_versioned_payload(self):
        with tempfile.TemporaryDirectory() as home:
            result = self.run_cli(home, "install", "guard")
            stable = os.path.join(home, ".local", "share", "onbelay", VERSION)
            self.assertEqual(result.returncode, 0)
            self.assertTrue(os.path.isfile(os.path.join(stable, "install.sh")))
            hook = os.path.join(home, ".claude", "hooks", "guard-bash.py")
            self.assertTrue(os.path.islink(hook))
            self.assertTrue(os.readlink(hook).startswith(stable + os.sep))
            self.run_cli(home, "doctor", "guard")
            self.run_cli(home, "uninstall", "guard")
            self.assertFalse(os.path.lexists(hook))

    def test_bare_doctor_checks_the_profile_that_is_installed(self):
        """`doctor` with no argument, on a guard-only machine.

        It used to default to standard/full and report 30 problems on a
        machine with nothing wrong, exit 1, and tell the user to run
        `./install.sh standard`: a file an npx user does not have, naming the
        13 skills they had deliberately opted out of. The README gives
        `install guard` its own section and offers exactly one way to check
        it, so this was the check being broken for the install being
        recommended to the most skeptical reader.
        """
        with tempfile.TemporaryDirectory() as home:
            self.run_cli(home, "install", "guard")
            result = self.run_cli(home, "doctor", check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("all good", result.stdout)
            # ...and the remediation it prints names the install method used.
            broken = os.path.join(home, ".claude", "hooks", "guard-bash.py")
            os.remove(broken)
            result = self.run_cli(home, "doctor", check=False)
            self.assertEqual(result.returncode, 1)
            self.assertIn("npx @sid-thephysicskid/onbelay", result.stdout)
            self.assertNotIn("./install.sh", result.stdout)

    def test_doctor_rejects_extras_with_an_explicit_profile(self):
        """parseProfile SHIFTS the profile off, so testing args[0] afterwards
        tested the wrong token: `doctor guard --extras` ignored both the
        conflict and the flag and checked `full`. install() has always used
        `includes`; doctor did not."""
        with tempfile.TemporaryDirectory() as home:
            self.run_cli(home, "install", "guard")
            result = self.run_cli(home, "doctor", "guard", "--extras", check=False)
            self.assertEqual(result.returncode, 1)
            self.assertIn("cannot be combined", result.stderr)

    def test_init_creates_one_project_contract_for_both_hosts(self):
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as project:
            self.run_cli(home, "init", cwd=project)
            agents = os.path.join(project, "AGENTS.md")
            claude = os.path.join(project, "CLAUDE.md")
            self.assertTrue(os.path.isfile(agents))
            self.assertTrue(os.path.islink(claude))
            self.assertEqual(os.readlink(claude), "AGENTS.md")

    def test_existing_staged_payload_must_match_the_package(self):
        with tempfile.TemporaryDirectory() as home:
            self.run_cli(home, "install", "guard")
            staged = os.path.join(home, ".local", "share", "onbelay",
                                  VERSION, "install.sh")
            with open(staged, "a", encoding="utf-8") as fh:
                fh.write("\n# tampered\n")
            result = self.run_cli(home, "install", "guard", check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match the published package", result.stderr)

    def test_pack_contains_runtime_and_excludes_private_working_state(self):
        result = subprocess.run(
            ["npm", "pack", "--dry-run", "--json", "--ignore-scripts"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        files = {entry["path"] for entry in packed(result.stdout)["files"]}
        self.assertIn("bin/onbelay.js", files)
        self.assertIn("hooks/guard-bash.py", files)
        self.assertIn("skills/ship/SKILL.md", files)
        self.assertIn("scripts/manage_conflicts.py", files)
        self.assertIn("scripts/manage_instructions.py", files)
        self.assertIn("templates/AGENTS.global.md", files)
        self.assertNotIn("PRODUCT.md", files)
        self.assertFalse(any(path.startswith("evals/") for path in files))
        self.assertFalse(any(path.startswith("tests/") for path in files))
        self.assertFalse(any(".lavish" in path for path in files))
        self.assertFalse(any("__pycache__" in path for path in files))
        self.assertFalse(any(path.endswith((".pyc", ".pyo")) for path in files))

    def test_packed_tarball_runs_through_npx(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                ["npm", "pack", "--json", "--ignore-scripts",
                 "--pack-destination", directory],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
            )
            tarball = os.path.join(directory, packed(result.stdout)["filename"])
            home = os.path.join(directory, "home")
            os.mkdir(home)
            env = dict(os.environ, HOME=home,
                       npm_config_cache=os.path.join(directory, "npm-cache"))
            executed = subprocess.run(
                ["npx", "--yes", "--package", tarball,
                 "onbelay", "--version"],
                cwd=directory,
                env=env,
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertEqual(executed.stdout.strip(), VERSION)

    def test_packed_tarball_installs_and_removes_standard_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                ["npm", "pack", "--json", "--ignore-scripts",
                 "--pack-destination", directory],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
            )
            tarball = os.path.join(directory, packed(result.stdout)["filename"])
            home = os.path.join(directory, "home")
            os.mkdir(home)
            os.makedirs(os.path.join(home, ".claude", "skills", "review"))
            instructions = os.path.join(home, ".claude", "CLAUDE.md")
            original_instructions = b"My instructions.  \n\n"
            Path(instructions).write_bytes(original_instructions)
            Path(home, ".claude", "skills", "review", "SKILL.md").write_text(
                "existing review\n", encoding="utf-8")
            env = dict(os.environ, HOME=home,
                       npm_config_cache=os.path.join(directory, "npm-cache"),
                       PYTHONDONTWRITEBYTECODE="1")
            prefix = ["npx", "--yes", "--package", tarball, "onbelay"]
            subprocess.run(prefix + ["install", "--replace-conflicts"], cwd=directory, env=env,
                           text=True, capture_output=True, check=True)
            hook = os.path.join(home, ".claude", "hooks", "guard-bash.py")
            stable = os.path.join(home, ".local", "share", "onbelay", VERSION)
            self.assertTrue(os.path.islink(hook))
            self.assertTrue(os.readlink(hook).startswith(stable + os.sep))
            self.assertTrue(os.path.islink(os.path.join(
                home, ".claude", "skills", "ship")))
            self.assertIn("onbelay:start", Path(instructions).read_text(
                encoding="utf-8"))
            subprocess.run(prefix + ["doctor"], cwd=directory, env=env,
                           text=True, capture_output=True, check=True)
            subprocess.run(prefix + ["uninstall"], cwd=directory, env=env,
                           text=True, capture_output=True, check=True)
            self.assertFalse(os.path.lexists(hook))
            self.assertEqual(Path(instructions).read_bytes(), original_instructions)
            self.assertEqual(Path(home, ".claude", "skills", "review", "SKILL.md").read_text(
                encoding="utf-8"), "existing review\n")

    def test_unknown_options_fail_without_installing(self):
        with tempfile.TemporaryDirectory() as home:
            result = self.run_cli(home, "install", "guard", "--dry-run", check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unknown install option", result.stderr)
            self.assertFalse(os.path.exists(os.path.join(home, ".local", "share",
                                                        "onbelay")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
