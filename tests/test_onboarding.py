#!/usr/bin/env python3
"""User-facing installation contract for a clean or already-used machine."""

import os
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "bin", "onbelay.js")
WORKFLOW = (
    "navigate", "prototype", "bootstrap", "setup", "to-spec", "breakdown",
    "domain-modeling", "architect", "tdd", "diagnose", "review", "unstick",
    "ship",
)


class OnboardingTest(unittest.TestCase):
    def run_cli(self, home, *args, check=True, env=None):
        run_env = dict(
            os.environ,
            HOME=home,
            PYTHONDONTWRITEBYTECODE="1",
            ONBELAY_NONINTERACTIVE="1",
        )
        run_env.update(env or {})
        return subprocess.run(
            ["node", CLI, *args], cwd=ROOT, env=run_env, text=True,
            capture_output=True, check=check,
        )

    def test_one_command_installs_guard_workflow_and_routing(self):
        with tempfile.TemporaryDirectory() as home:
            result = self.run_cli(home, "install")
            for host in (".claude", ".codex"):
                for skill in WORKFLOW:
                    self.assertTrue(os.path.lexists(
                        os.path.join(home, host, "skills", skill)))
            self.assertTrue(os.path.lexists(
                os.path.join(home, ".claude", "hooks", "guard-bash.py")))
            claude = os.path.join(home, ".claude", "CLAUDE.md")
            codex = os.path.join(home, ".codex", "AGENTS.md")
            self.assertTrue(os.path.islink(claude))
            self.assertTrue(os.path.islink(codex))
            self.assertEqual(os.path.realpath(claude), os.path.realpath(codex))
            self.assertIn("Guard active", result.stdout)
            self.assertIn("Workflow active: 13/13", result.stdout)
            self.assertIn("Claude Code + Codex routing active", result.stdout)

    def test_extras_are_explicit(self):
        with tempfile.TemporaryDirectory() as home:
            self.run_cli(home, "install")
            self.assertFalse(os.path.lexists(
                os.path.join(home, ".claude", "skills", "wizard")))
            self.run_cli(home, "install", "--extras")
            for skill in ("research", "wizard", "handoff"):
                self.assertTrue(os.path.lexists(
                    os.path.join(home, ".claude", "skills", skill)))
            self.run_cli(home, "doctor")
            os.unlink(os.path.join(home, ".claude", "skills", "research"))
            self.assertNotEqual(
                self.run_cli(home, "doctor", check=False).returncode, 0)

    def test_existing_instructions_are_preserved_with_one_managed_block(self):
        with tempfile.TemporaryDirectory() as home:
            os.makedirs(os.path.join(home, ".claude"))
            os.makedirs(os.path.join(home, ".codex"))
            claude = os.path.join(home, ".claude", "CLAUDE.md")
            codex = os.path.join(home, ".codex", "AGENTS.md")
            with open(claude, "w", encoding="utf-8") as fh:
                fh.write("My Claude preferences.\n")
            with open(codex, "w", encoding="utf-8") as fh:
                fh.write("My Codex preferences.\n")

            self.run_cli(home, "install")
            self.run_cli(home, "install")
            for path, original in ((claude, "My Claude preferences."),
                                   (codex, "My Codex preferences.")):
                text = Path(path).read_text(encoding="utf-8")
                self.assertIn(original, text)
                self.assertEqual(text.count("onbelay:start"), 1)

            self.run_cli(home, "uninstall")
            self.assertEqual(Path(claude).read_text(encoding="utf-8"),
                             "My Claude preferences.\n")
            self.assertEqual(Path(codex).read_text(encoding="utf-8"),
                             "My Codex preferences.\n")

    def test_malformed_instruction_markers_abort_before_wiring(self):
        with tempfile.TemporaryDirectory() as home:
            os.makedirs(os.path.join(home, ".claude"))
            instructions = os.path.join(home, ".claude", "CLAUDE.md")
            Path(instructions).write_text(
                "mine\n<!-- onbelay:start -->\nbroken\n", encoding="utf-8")
            result = self.run_cli(home, "install", check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(os.path.lexists(
                os.path.join(home, ".claude", "skills", "ship")))
            self.assertFalse(os.path.exists(
                os.path.join(home, ".claude", "settings.json")))

    def test_noninteractive_skill_collision_is_kept_and_install_continues(self):
        with tempfile.TemporaryDirectory() as home:
            collision = os.path.join(home, ".claude", "skills", "review")
            os.makedirs(collision)
            with open(os.path.join(collision, "SKILL.md"), "w", encoding="utf-8") as fh:
                fh.write("theirs\n")
            result = self.run_cli(home, "install")
            self.assertEqual(Path(collision, "SKILL.md").read_text(
                encoding="utf-8"), "theirs\n")
            self.assertTrue(os.path.lexists(
                os.path.join(home, ".claude", "skills", "ship")))
            self.assertIn("kept 1 existing skill", result.stdout)

    def test_replace_conflicts_is_reversible(self):
        with tempfile.TemporaryDirectory() as home:
            collision = os.path.join(home, ".claude", "skills", "review")
            os.makedirs(collision)
            with open(os.path.join(collision, "SKILL.md"), "w", encoding="utf-8") as fh:
                fh.write("theirs\n")
            self.run_cli(home, "install", "--replace-conflicts")
            self.assertTrue(os.path.islink(collision))
            self.run_cli(home, "uninstall")
            self.assertFalse(os.path.islink(collision))
            self.assertEqual(Path(collision, "SKILL.md").read_text(
                encoding="utf-8"), "theirs\n")

    def test_dangling_skill_link_is_preserved_or_restored(self):
        with tempfile.TemporaryDirectory() as home:
            collision = os.path.join(home, ".claude", "skills", "review")
            os.makedirs(os.path.dirname(collision))
            original_target = os.path.join(home, "missing-user-skill")
            os.symlink(original_target, collision)

            self.run_cli(home, "install")
            self.assertEqual(os.readlink(collision), original_target)

            self.run_cli(home, "install", "--replace-conflicts")
            self.assertNotEqual(os.readlink(collision), original_target)
            self.run_cli(home, "uninstall")
            self.assertEqual(os.readlink(collision), original_target)

    def test_dotfile_managed_skill_directories_are_supported(self):
        with tempfile.TemporaryDirectory() as home:
            dots = os.path.join(home, "dotfiles")
            os.makedirs(os.path.join(dots, "claude-skills"))
            os.makedirs(os.path.join(dots, "codex-skills"))
            os.makedirs(os.path.join(home, ".claude"))
            os.makedirs(os.path.join(home, ".codex"))
            os.symlink(os.path.join(dots, "claude-skills"),
                       os.path.join(home, ".claude", "skills"))
            os.symlink(os.path.join(dots, "codex-skills"),
                       os.path.join(home, ".codex", "skills"))
            self.run_cli(home, "install")
            self.assertTrue(os.path.islink(os.path.join(home, ".claude", "skills")))
            self.assertTrue(os.path.lexists(
                os.path.join(dots, "claude-skills", "ship")))

    def test_custom_agent_homes_are_respected(self):
        with tempfile.TemporaryDirectory() as home:
            claude_home = os.path.join(home, "claude-config")
            codex_home = os.path.join(home, "codex-config")
            self.run_cli(
                home, "install",
                env={"CLAUDE_CONFIG_DIR": claude_home, "CODEX_HOME": codex_home},
            )
            self.assertTrue(os.path.lexists(
                os.path.join(claude_home, "skills", "ship")))
            self.assertTrue(os.path.lexists(
                os.path.join(codex_home, "skills", "ship")))
            settings = json.loads(Path(
                claude_home, "settings.json").read_text(encoding="utf-8"))
            command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            payload = json.dumps({
                "tool_name": "Bash",
                "tool_input": {"command": f"rm -f {claude_home}/hooks/guard-bash.py"},
                "cwd": home,
            })
            blocked = subprocess.run(
                ["bash", "-c", command], input=payload, text=True,
                capture_output=True,
                env=dict(os.environ, HOME=home, CLAUDE_CONFIG_DIR=claude_home,
                         CODEX_HOME=codex_home, PYTHONDONTWRITEBYTECODE="1"),
            )
            self.assertEqual(blocked.returncode, 2, blocked.stderr)

    def test_custom_home_finds_an_older_installed_payload(self):
        with tempfile.TemporaryDirectory() as home:
            claude_home = os.path.join(home, "claude-config")
            codex_home = os.path.join(home, "codex-config")
            env = {"CLAUDE_CONFIG_DIR": claude_home, "CODEX_HOME": codex_home}
            subprocess.run(
                ["bash", os.path.join(ROOT, "install.sh"), "standard"],
                cwd=ROOT,
                env=dict(os.environ, HOME=home, CLAUDE_CONFIG_DIR=claude_home,
                         CODEX_HOME=codex_home, ONBELAY_NONINTERACTIVE="1"),
                text=True,
                capture_output=True,
                check=True,
            )

            self.run_cli(home, "uninstall", env=env)

            self.assertFalse(os.path.lexists(
                os.path.join(claude_home, "skills", "ship")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
