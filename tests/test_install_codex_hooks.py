#!/usr/bin/env python3
"""Codex hooks.json merge and strip behavior."""
import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import install_codex_hooks as H  # noqa: E402


class CodexHooksTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.original = {
            "description": "mine",
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{
                        "type": "command",
                        "command": "python3 ~/mine/audit.py",
                    }],
                }],
            },
        }
        with open(self.path, "w") as f:
            json.dump(self.original, f)

    def tearDown(self):
        for path in (self.path, self.path + ".tmp"):
            if os.path.exists(path):
                os.unlink(path)

    def read(self):
        with open(self.path) as f:
            return json.load(f)

    def commands(self, event):
        return [
            hook.get("command", "")
            for group in self.read().get("hooks", {}).get(event, [])
            for hook in group.get("hooks", [])
        ]

    def test_existing_hook_survives_merge_and_strip(self):
        H.merge(self.path, "/opt/onbelay")
        self.assertIn("python3 ~/mine/audit.py", self.commands("PreToolUse"))

        H.strip(self.path)
        self.assertEqual(self.read(), self.original)

    def test_installs_only_the_pre_tool_guard(self):
        H.merge(self.path, "/opt/onbelay")
        cfg = self.read()
        commands = [hook["command"]
                    for group in cfg["hooks"].get("PreToolUse", [])
                    for hook in group["hooks"]]
        self.assertTrue(any("guard-codex.py" in c
                            for c in commands))
        self.assertNotIn("Stop", cfg["hooks"])
        self.assertNotIn("SessionStart", cfg["hooks"])

    def test_merge_is_idempotent(self):
        H.merge(self.path, "/opt/onbelay")
        first = self.read()
        for _ in range(3):
            H.merge(self.path, "/opt/onbelay")
        self.assertEqual(self.read(), first)

    def test_relocation_replaces_only_our_old_commands(self):
        H.merge(self.path, "/old/onbelay")
        H.merge(self.path, "/new/onbelay")
        rendered = json.dumps(self.read())
        self.assertNotIn("/old/onbelay", rendered)
        self.assertIn("/new/onbelay", rendered)
        self.assertIn("python3 ~/mine/audit.py", rendered)

    def test_upgrades_the_previous_exclusive_file_and_still_uninstalls_cleanly(self):
        legacy = {
            "description": "Guardrails shared with Claude Code via onbelay/hooks",
            "hooks": {
                "PreToolUse": [{
                    "matcher": ".*",
                    "hooks": [{
                        "type": "command",
                        "command": H._legacy_command(
                            "/old/onbelay", "guard-codex.py"),
                        "timeout": 5,
                        "statusMessage": "Checking guardrails...",
                    }],
                }],
            },
        }
        with open(self.path, "w") as f:
            json.dump(legacy, f)
        H.merge(self.path, "/new/onbelay")
        self.assertEqual(self.read()["description"], H.DESCRIPTION)
        H.strip(self.path)
        self.assertFalse(os.path.exists(self.path))

    def test_a_command_that_only_mentions_our_script_is_not_removed(self):
        theirs = "python3 ~/mine/wrap.py --after hooks/guard-codex.py"
        self.original["hooks"]["PreToolUse"][0]["hooks"].append({
            "type": "command",
            "command": theirs,
        })
        with open(self.path, "w") as f:
            json.dump(self.original, f)
        H.merge(self.path, "/opt/onbelay")
        H.strip(self.path)
        self.assertIn(theirs, self.commands("PreToolUse"))

    def test_an_unrelated_hook_with_the_same_script_name_is_not_removed(self):
        theirs = H._legacy_command("/opt/not-onbelay", "welcome.py")
        self.original["hooks"]["SessionStart"] = [{
            "hooks": [{
                "type": "command",
                "command": theirs,
                "timeout": 5,
                "statusMessage": "Loading onbelay...",
            }],
        }]
        with open(self.path, "w") as f:
            json.dump(self.original, f)
        H.merge(self.path, "/opt/onbelay")
        H.strip(self.path)
        self.assertIn(theirs, self.commands("SessionStart"))

    def test_new_file_is_removed_on_strip(self):
        os.unlink(self.path)
        H.merge(self.path, "/opt/onbelay")
        self.assertTrue(os.path.exists(self.path))
        H.strip(self.path)
        self.assertFalse(os.path.exists(self.path))

    def test_owned_description_is_removed_when_user_keys_remain(self):
        os.unlink(self.path)
        H.merge(self.path, "/opt/onbelay")
        cfg = self.read()
        cfg["theme"] = "mine"
        with open(self.path, "w") as f:
            json.dump(cfg, f)
        H.strip(self.path)
        self.assertEqual(self.read(), {"theme": "mine"})

    def test_merge_preserves_existing_file_mode(self):
        os.chmod(self.path, 0o600)
        H.merge(self.path, "/opt/onbelay")
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_command_quotes_an_apostrophe_in_the_repo_path(self):
        command = H._command("/opt/sid's config", "guard-codex.py")
        self.assertIn("sid'\"'\"'s config", command)

    def test_check_requires_the_current_definition(self):
        H.merge(self.path, "/opt/onbelay")
        self.assertTrue(H.check(self.path, "/opt/onbelay"))
        cfg = self.read()
        cfg["hooks"]["PreToolUse"] = [cfg["hooks"]["PreToolUse"][0]]
        with open(self.path, "w") as f:
            json.dump(cfg, f)
        self.assertFalse(H.check(self.path, "/opt/onbelay"))

    def test_merge_removes_retired_tagged_lifecycle_hooks(self):
        self.original["hooks"]["Stop"] = [{"hooks": [{
            "type": "command",
            "command": H._command("/old/onbelay", "check-docs.py"),
            "timeout": 130,
            "statusMessage": "Checking documentation...",
        }]}]
        with open(self.path, "w") as f:
            json.dump(self.original, f)
        H.merge(self.path, "/new/onbelay")
        self.assertNotIn("Stop", self.read()["hooks"])

    def test_rejects_a_malformed_user_hook_before_rewriting(self):
        malformed = {"hooks": {"PreToolUse": [{"hooks": ["not an object"]}]}}
        with open(self.path, "w") as f:
            json.dump(malformed, f)
        with open(self.path) as f:
            before = f.read()
        with self.assertRaises(ValueError):
            H.merge(self.path, "/opt/onbelay")
        with open(self.path) as f:
            self.assertEqual(f.read(), before)

    def test_updates_a_symlink_target_without_detaching_it(self):
        target = self.path + ".target"
        os.rename(self.path, target)
        os.symlink(target, self.path)
        try:
            H.merge(self.path, "/opt/onbelay")
            self.assertTrue(os.path.islink(self.path))
            self.assertTrue(H.check(self.path, "/opt/onbelay"))
        finally:
            os.unlink(self.path)
            os.unlink(target)


if __name__ == "__main__":
    unittest.main(verbosity=2)
