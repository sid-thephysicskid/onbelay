#!/usr/bin/env python3
"""Release metadata and native plugin surfaces stay synchronized."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ReleaseMetadataTest(unittest.TestCase):
    def test_versions_match(self):
        with open(os.path.join(ROOT, "VERSION")) as fh:
            version = fh.read().strip()
        with open(os.path.join(ROOT, "package.json")) as fh:
            package = json.load(fh)
        self.assertEqual(package["version"], version)
        self.assertEqual(package["name"], "@sid-thephysicskid/onbelay")
        self.assertEqual(package["publishConfig"]["access"], "public")

    def test_npm_publish_uses_oidc_and_a_public_release(self):
        path = os.path.join(ROOT, ".github", "workflows", "publish.yml")
        with open(path) as fh:
            workflow = fh.read()
        self.assertIn("release:\n    types: [published]", workflow)
        self.assertIn("id-token: write", workflow)
        # registry-url is REQUIRED while publishing by token: it is what makes
        # setup-node write the .npmrc that consumes NODE_AUTH_TOKEN. It is
        # also what breaks OIDC, so these two assertions flip together or
        # neither does. Two releases failed with a 404 from having one
        # without the other.
        # Assert against the YAML, not the prose. The comments in that file
        # name both traps, so a substring check matches its own explanation.
        directives = "\n".join(line for line in workflow.splitlines()
                               if not line.lstrip().startswith("#"))
        self.assertIn("registry-url", directives)
        self.assertIn("GITHUB_REF_NAME", workflow)
        self.assertIn('require("./package.json").version', workflow)
        self.assertIn("./scripts/gates --full", workflow)
        self.assertIn("npm publish", workflow)
        # A token, deliberately, and temporarily. Registering a trusted
        # publisher needs a typed 6-digit code that this account cannot
        # produce (passkey, and `npm trust` has no browser fallback), and a
        # package that does not exist yet cannot be configured from the
        # website. The token is what creates the package. When trusted
        # publishing is configured, these three assertions invert again and
        # the secret is deleted. RELEASING.md carries the sequence.
        self.assertIn("NODE_AUTH_TOKEN", directives)
        self.assertIn("NPM_TOKEN", directives)
        # The reminder to remove the secret goes with the secret. What is
        # pinned instead is the permission OIDC needs, because losing that
        # breaks publishing in a way whose error message says 404.
        self.assertIn("id-token: write", workflow)

    def test_bootstrap_and_setup_own_the_project_contract(self):
        with open(os.path.join(ROOT, "skills", "bootstrap", "SKILL.md")) as fh:
            bootstrap = fh.read()
        with open(os.path.join(ROOT, "skills", "setup", "SKILL.md")) as fh:
            setup = fh.read()
        self.assertIn("replaces the initializer's generic project-contract", bootstrap)
        self.assertIn("replace its generic `## Project\ncontract` section", setup)

    def test_public_release_builder_is_tracked_and_executable(self):
        path = os.path.join(ROOT, "scripts", "build-public-release")
        self.assertTrue(os.path.isfile(path))
        self.assertTrue(os.access(path, os.X_OK))

    def test_public_release_builder_exports_clean_history_free_source(self):
        with tempfile.TemporaryDirectory() as parent:
            repo = os.path.join(parent, "repo")
            export = os.path.join(parent, "public")
            shutil.copytree(ROOT, repo, ignore=shutil.ignore_patterns(
                ".git", ".claude", "__pycache__", "node_modules", "*.pyc"))
            for command in (
                    ["git", "init", "-b", "main"],
                    ["git", "config", "user.email", "release@example.com"],
                    ["git", "config", "user.name", "Release Test"],
                    ["git", "add", "--all"],
                    ["git", "commit", "-m", "test: release fixture"]):
                subprocess.run(command, cwd=repo, check=True,
                               capture_output=True, text=True)
            for unsafe in ("public", os.path.join(parent, "repo-link", "public")):
                if "repo-link" in unsafe:
                    os.symlink(repo, os.path.join(parent, "repo-link"))
                refused = subprocess.run(
                    [os.path.join(repo, "scripts", "build-public-release"), unsafe],
                    cwd=repo,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn("Refusing unsafe destination", refused.stderr)
                self.assertFalse(os.path.lexists(os.path.join(repo, "public")))
            result = subprocess.run(
                [os.path.join(repo, "scripts", "build-public-release"), export],
                cwd=repo,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(os.path.exists(os.path.join(export, ".git")))
            self.assertTrue(os.path.isfile(os.path.join(export, "package.json")))
            self.assertIn("no Git history", result.stdout)

    def test_public_audit_scans_a_history_free_tree(self):
        with tempfile.TemporaryDirectory() as parent:
            export = os.path.join(parent, "export")
            shutil.copytree(ROOT, export, ignore=shutil.ignore_patterns(
                ".git", ".claude", "__pycache__", "node_modules", "*.pyc"))
            result = subprocess.run(
                ["python3", os.path.join(export, "tests", "audit.py")],
                cwd=export,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("audit: 0 tracked files", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
