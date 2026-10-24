"""Tests for the duplicate-code ratchet, including the real jscpd binary."""
from __future__ import annotations

import tomllib
import unittest

from support import (
    FixtureCase,
    baseline_text,
    output,
    sarif_report,
    with_clones,
)

ELISP_SOURCE = """\
;;; sample.el --- file summary -*- lexical-binding: t; -*-
(defun qg-summarize-files (paths)
  "Return a summary of PATHS."
  (let ((count 0)
        (total 0))
    (dolist (path paths)
      (when (file-regular-p path)
        (setq count (1+ count))
        (setq total (+ total (file-attribute-size (file-attributes path))))))
    (format "%d files, %d bytes" count total)))
(provide 'sample)
;;; sample.el ends here
"""

SHELL_SOURCE = """\
#!/bin/bash
set -euo pipefail
summarize_files() {
  local count=0
  local total=0
  for path in "$@"; do
    if [[ -f "$path" ]]; then
      count=$((count + 1))
      total=$((total + $(wc -c < "$path")))
    fi
  done
  printf '%s files, %s bytes\\n' "$count" "$total"
}
summarize_files "$@"
"""


class CloneGateTests(FixtureCase):
    def clone_env(
        self,
        clones: list[tuple[str, list[tuple[str, int, int]]]],
        entries: list[dict[str, object]] | None = None,
        *,
        classes: str = '["python"]',
        min_tokens: int = 50,
        baseline: str = "quality-gate-clones.toml",
        fake: dict[str, object] | None = None,
    ) -> dict[str, str]:
        self.add_file("b.py", "print('b')\n")
        self.write_config(
            with_clones(
                classes=classes,
                min_tokens=min_tokens,
                baseline=baseline,
            )
        )
        if entries is not None:
            self.add_file(baseline, baseline_text(entries))
        return self.install_fake_jscpd(
            sarif_report(clones), **(fake or {})
        )

    def clone_failure(
        self, env: dict[str, str], *needles: str, prune: bool = False
    ) -> str:
        command = ("clones", "--prune") if prune else ("clones",)
        result = self.run_qg(*command, env=env)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        for needle in needles:
            self.assertIn(needle, text)
        return text

    def single_baseline(self, fingerprint: str, reason: str) -> dict[str, object]:
        entries = tomllib.loads(
            self.read_file("quality-gate-clones.toml")
        )["clone"]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["fingerprint"], fingerprint)
        self.assertEqual(entry["count"], 1)
        self.assertEqual(entry["reason"], reason)
        return entry

    def test_baselined_clone_passes(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])],
            [
                {
                    "fingerprint": "fp1",
                    "files": ["a.py", "b.py"],
                    "reason": "deliberate mirror",
                }
            ],
        )
        result = self.run_qg("clones", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("clones: 1 clone within baseline", result.stdout)

    def test_new_clone_fails_with_files_and_ranges(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 2, 9)])]
        )
        self.clone_failure(env, "new clone fp1", "a.py:1-8", "b.py:2-9")

    def repeated_clone_env(
        self,
        entries: list[dict[str, object]],
        extra: tuple[str, list[tuple[str, int, int]]] | None = None,
    ) -> dict[str, str]:
        clones = [
            ("fp1", [("a.py", 1, 8), ("b.py", 1, 8)]),
            ("fp1", [("a.py", 1, 8), ("c.py", 1, 8)]),
        ]
        if extra is not None:
            clones.append(extra)
        env = self.clone_env(clones, entries)
        self.add_file("c.py", "print('c')\n")
        return env

    def test_count_exceeded_fails(self) -> None:
        env = self.repeated_clone_env(
            [{"fingerprint": "fp1", "reason": "one accepted copy"}]
        )
        self.clone_failure(
            env, "occurs 2 times", "b.py:1-8", "c.py:1-8"
        )

    def test_count_allows_repeated_fingerprint(self) -> None:
        env = self.repeated_clone_env(
            [{"fingerprint": "fp1", "count": 2, "reason": "two accepted copies"}]
        )
        result = self.run_qg("clones", env=env)
        self.assertEqual(result.returncode, 0, output(result))

    def test_empty_baseline_reason_fails(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])],
            [{"fingerprint": "fp1", "reason": "   "}],
        )
        self.clone_failure(
            env, "empty reason", "a.py:1-8", "b.py:1-8"
        )

    def test_resolved_entry_is_reported_but_passes(self) -> None:
        env = self.clone_env(
            [],
            [{"fingerprint": "fp-old", "files": ["old.py"], "reason": "gone"}],
        )
        result = self.run_qg("clones", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("resolved fp-old", result.stdout)

    def test_resolved_entry_with_empty_reason_fails(self) -> None:
        env = self.clone_env(
            [],
            [{"fingerprint": "fp-old", "files": ["old.py"], "reason": "   "}],
        )
        text = self.clone_failure(env, "empty reason", "resolved fp-old")
        self.assertIn("files: old.py", text)

    def test_absent_baseline_with_no_clones_passes(self) -> None:
        env = self.clone_env([])
        result = self.run_qg("clones", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("clones: 0 clones", result.stdout)

    def test_absent_baseline_with_clone_fails(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])]
        )
        self.clone_failure(env, "new clone fp1")

    def test_jscpd_nonzero_exit_fails(self) -> None:
        env = self.clone_env(
            [],
            fake={"exit_code": 3, "error": "boom from jscpd"},
        )
        self.clone_failure(env, "jscpd failed (exit 3)", "boom from jscpd")

    def test_jscpd_without_report_fails(self) -> None:
        env = self.clone_env([], fake={"report": False})
        self.clone_failure(env, "wrote no report")

    def test_jscpd_empty_analysis_fails(self) -> None:
        env = self.clone_env(
            [],
            fake={
                "exit_code": 1,
                "error": "ERROR: jscpd analyzed no files (--fail-on-empty)",
            },
        )
        self.clone_failure(env, "jscpd failed", "analyzed no files")

    def test_jscpd_is_invoked_with_the_gate_options_and_files(self) -> None:
        args_file = self.base / "jscpd-args.txt"
        env = self.clone_env(
            [],
            min_tokens=77,
            fake={"args_file": args_file},
        )
        result = self.run_qg("clones", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        arguments = args_file.read_text(encoding="utf-8").split("\n")
        self.assertIn("--fail-on-empty", arguments)
        self.assertIn("--reporters", arguments)
        self.assertIn("sarif", arguments)
        index = arguments.index("--min-tokens")
        self.assertEqual(arguments[index + 1], "77")
        separator = arguments.index("--")
        self.assertIn("a.py", arguments[separator + 1:])

    def test_invalid_sarif_fails(self) -> None:
        env = self.clone_env([], fake={})
        sarif_path = self.base / "sarif.json"
        sarif_path.write_text('{"version": "2.1.0"}', encoding="utf-8")
        self.clone_failure(env, "invalid SARIF")

    def test_sarif_without_fingerprint_fails(self) -> None:
        env = self.clone_env([], fake={})
        sarif_path = self.base / "sarif.json"
        sarif_path.write_text(
            '{"version": "2.1.0", "runs": [{"results": [{}]}]}',
            encoding="utf-8",
        )
        self.clone_failure(env, "jscpdCloneHash/v1")

    def test_prune_removes_resolved_entries_and_lowers_count(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])],
            [
                {
                    "fingerprint": "fp1",
                    "count": 3,
                    "files": ["a.py", "b.py"],
                    "reason": "deliberate mirror",
                },
                {
                    "fingerprint": "fp-old",
                    "files": ["old.py"],
                    "reason": "gone",
                },
            ],
        )
        result = self.run_qg("clones", "--prune", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        entry = self.single_baseline("fp1", "deliberate mirror")
        self.assertEqual(entry["files"], ["a.py", "b.py"])

    def test_prune_removes_an_empty_baseline(self) -> None:
        env = self.clone_env(
            [],
            [{"fingerprint": "fp-old", "reason": "gone"}],
        )
        result = self.run_qg("clones", "--prune", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse((self.repo / "quality-gate-clones.toml").exists())
        self.assertIn("baseline removed", result.stdout)

    def test_prune_with_absent_baseline_creates_nothing(self) -> None:
        env = self.clone_env([])
        result = self.run_qg("clones", "--prune", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse((self.repo / "quality-gate-clones.toml").exists())
        self.assertNotIn("baseline removed", result.stdout)

    def test_prune_never_adds_or_raises_an_entry(self) -> None:
        env = self.repeated_clone_env(
            [{"fingerprint": "fp1", "reason": "one accepted copy"}],
            extra=("fp-new", [("d.py", 1, 8), ("e.py", 1, 8)]),
        )
        self.add_file("d.py", "print('d')\n")
        self.add_file("e.py", "print('e')\n")
        text = self.clone_failure(env, "new clone fp-new", prune=True)
        self.single_baseline("fp1", "one accepted copy")
        self.assertNotIn("fp-new", self.read_file("quality-gate-clones.toml"))
        self.assertIn("occurs 2 times", text)

    def test_prune_does_not_rewrite_with_an_empty_reason(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])],
            [
                {"fingerprint": "fp1", "reason": "   "},
                {"fingerprint": "fp-old", "reason": "gone"},
            ],
        )
        before = self.read_file("quality-gate-clones.toml")
        self.clone_failure(env, "empty reason", prune=True)
        self.assertEqual(self.read_file("quality-gate-clones.toml"), before)

    def test_enumeration_failure_fails_clones(self) -> None:
        self.write_config(with_clones())
        env = self.fake_git_failing_ls_files()
        self.clone_failure(env, "file enumeration failed")

    def test_missing_tool_names_tools_fetch(self) -> None:
        self.write_config(with_clones())
        env = {"QG_TOOLS_DIR": str(self.base / "empty-tools")}
        self.clone_failure(env, "tools fetch")

    def test_clones_not_configured_exits_2(self) -> None:
        result = self.run_qg("clones")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("[clones] is not configured", text)

    def test_invalid_inventory_blocks_clones(self) -> None:
        self.add_file("mystery.txt", "x\n")
        self.write_config(with_clones())
        self.clone_failure({}, "clones: inventory:", "mystery.txt")

    def test_no_files_in_clone_classes_fails(self) -> None:
        self.write_config(
            with_clones(classes='["empty"]').replace(
                "[classes.python]",
                '[classes.empty]\ncode = true\ndescription = "Empty"\n\n'
                "[classes.python]",
            )
        )
        self.clone_failure({}, "no files in classes (empty)")

    def test_invalid_baseline_toml_fails(self) -> None:
        env = self.clone_env([])
        self.add_file("quality-gate-clones.toml", "[clone\n")
        self.clone_failure(env, "invalid baseline")

    def test_invalid_baseline_count_fails(self) -> None:
        env = self.clone_env([])
        self.add_file(
            "quality-gate-clones.toml",
            '[[clone]]\nfingerprint = "fp1"\ncount = -1\n'
            'reason = "never valid"\n',
        )
        self.clone_failure(env, "count", ">= 0")

    def test_zero_count_rejects_an_occurrence(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])],
            [{"fingerprint": "fp1", "count": 0, "reason": "nothing accepted"}],
        )
        self.clone_failure(
            env, "occurs 1 time", "baseline count is 0"
        )

    def test_real_jscpd_reports_elisp_and_bash_clone_pairs(self) -> None:
        self.write_config(
            """\
[code]
patterns = ["*.el", "*.sh"]
shebangs = ["sh", "bash"]

[classes.lisp]
code = true
description = "Emacs Lisp"

[classes.shell]
code = true
description = "Bash"

[classes.config]
code = false
description = "Configuration"

[[rule]]
pattern = "*.el"
class = "lisp"
reason = "Emacs Lisp source"

[[rule]]
pattern = "*.sh"
class = "shell"
reason = "Bash source"

[[rule]]
pattern = "*.toml"
class = "config"
reason = "Configuration"

[[rule]]
pattern = ".gitignore"
class = "config"
reason = "Ignore rules"

[clones]
classes = ["lisp", "shell"]
min_tokens = 50
baseline = "quality-gate-clones.toml"
"""
        )
        (self.repo / "a.py").unlink()
        (self.repo / "README.md").unlink()
        self.add_file("a.el", ELISP_SOURCE)
        self.add_file("b.el", ELISP_SOURCE)
        self.add_file("a.sh", SHELL_SOURCE)
        self.add_file("b.sh", SHELL_SOURCE)

        result = self.run_qg("clones", env=self.default_tool_env())
        text = output(result)
        if "not installed" in text and "tools fetch" in text:
            self.fail(
                "real jscpd is not installed; run python3 -I qg.py tools fetch: "
                + text
            )
        self.assertEqual(result.returncode, 1, text)
        for name in ("a.el", "b.el", "a.sh", "b.sh"):
            self.assertIn(name, text)
        self.assertIn("new clone", text)
        new_clone_lines = [
            line for line in text.splitlines() if "new clone" in line
        ]
        self.assertTrue(
            any(
                "a.el" in line and "b.el" in line
                for line in new_clone_lines
            ),
            text,
        )
        self.assertTrue(
            any(
                "a.sh" in line and "b.sh" in line
                for line in new_clone_lines
            ),
            text,
        )


if __name__ == "__main__":
    unittest.main()
