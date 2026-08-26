#!/usr/bin/env python3
"""Focused tests for reversible instruction and conflict state."""

import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import manage_conflicts as conflicts  # noqa: E402
import manage_instructions as instructions  # noqa: E402


class InstructionTest(unittest.TestCase):
    def test_round_trip_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "source.md")
            source.write_text("Use the workflow.\n", encoding="utf-8")
            path = Path(directory, "AGENTS.md")
            original = b"Keep these spaces.  \n\n\n"
            path.write_bytes(original)

            instructions.merge(str(path), str(source))
            instructions.strip(str(path))

            self.assertEqual(path.read_bytes(), original)

    def test_symlink_target_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "source.md")
            source.write_text("Use the workflow.\n", encoding="utf-8")
            target = Path(directory, "dotfiles", "CLAUDE.md")
            target.parent.mkdir()
            target.write_text("Mine.\n", encoding="utf-8")
            path = Path(directory, "CLAUDE.md")
            path.symlink_to(target)

            instructions.merge(str(path), str(source))
            self.assertTrue(path.is_symlink())
            self.assertTrue(instructions.check(str(path), str(source)))
            instructions.strip(str(path))
            self.assertEqual(target.read_text(encoding="utf-8"), "Mine.\n")

    def test_malformed_markers_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "AGENTS.md")
            path.write_text("<!-- onbelay:start -->\nbroken\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "malformed"):
                instructions.validate(str(path))


class ConflictTest(unittest.TestCase):
    def test_backup_and_restore_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            state = os.path.join(directory, "state", "conflicts.json")
            skill = Path(directory, "skills", "review")
            skill.mkdir(parents=True)
            Path(skill, "SKILL.md").write_text("theirs\n", encoding="utf-8")
            conflicts.backup(state, [str(skill)])
            self.assertFalse(skill.exists())
            conflicts.restore(state)
            self.assertEqual(Path(skill, "SKILL.md").read_text(encoding="utf-8"),
                             "theirs\n")
            self.assertFalse(os.path.lexists(state))

    def test_symlinked_state_is_refused_without_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            victim = Path(directory, "victim")
            victim.write_text("mine\n", encoding="utf-8")
            state = Path(directory, "conflicts.json")
            state.symlink_to(victim)
            skill = Path(directory, "skill")
            skill.mkdir()
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                conflicts.backup(str(state), [str(skill)])
            self.assertEqual(victim.read_text(encoding="utf-8"), "mine\n")
            self.assertTrue(skill.is_dir())


if __name__ == "__main__":
    unittest.main(verbosity=2)
