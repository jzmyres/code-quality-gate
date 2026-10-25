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

    def unsupported_clone(
        self, env: dict[str, str], *needles: str
    ) -> str:
        result, document = self.run_json(env=env)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertEqual(
            self.check_by_id(document, "clones")["outcome"], "unsupported"
        )
        for needle in needles:
            self.assertIn(needle, text)
        return text

    def single_baseline(self, fingerprint: str, reason: str) -> dict[str, object]:
        entries = tomllib.loads(
            self.read_file("quality-gate-clones.toml")
        )["entry"]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["subject"], fingerprint)
        self.assertEqual(entry["bound"], 1)
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
        self.write_config(
            with_clones(min_tokens=77).replace(
                "[code]",
                "[hygiene]\nmax_bytes = 12345\n\n[code]",
            )
        )
        env = self.install_fake_jscpd(
            sarif_report([]), args_file=args_file
        )
        result = self.run_qg("clones", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        arguments = args_file.read_text(encoding="utf-8").split("\n")
        self.assertIn("--fail-on-empty", arguments)
        self.assertIn("--reporters", arguments)
        self.assertIn("json,sarif", arguments)
        self.assertIn("--no-gitignore", arguments)
        self.assertIn("--config", arguments)
        index = arguments.index("--min-tokens")
        self.assertEqual(arguments[index + 1], "77")
        index = arguments.index("--min-lines")
        self.assertEqual(arguments[index + 1], "5")
        index = arguments.index("--max-size")
        self.assertEqual(arguments[index + 1], "12345")
        index = arguments.index("--ignore")
        self.assertTrue(arguments[index + 1])
        separator = arguments.index("--")
        self.assertIn("a.py", arguments[separator + 1:])

    def test_jscpd_source_count_mismatch_is_unsupported(self) -> None:
        env = self.clone_env(
            [],
            fake={
                "json_report": {
                    "statistics": {
                        "formats": {},
                        "total": {"sources": 1},
                    }
                }
            },
        )
        self.unsupported_clone(env, "not analysed", "b.py")

    def test_invalid_sarif_is_unsupported(self) -> None:
        env = self.clone_env([], fake={})
        sarif_path = self.base / "sarif.json"
        sarif_path.write_text('{"version": "2.1.0"}', encoding="utf-8")
        self.unsupported_clone(env, "no completed jscpd run")

    def test_sarif_without_fingerprint_is_unsupported(self) -> None:
        env = self.clone_env([], fake={})
        sarif_path = self.base / "sarif.json"
        sarif_path.write_text(
            '{"version": "2.1.0", "runs": ['
            '{"tool": {"driver": {"name": "jscpd"}}, "results": [{}]}]}',
            encoding="utf-8",
        )
        self.unsupported_clone(
            env, "no completed jscpd run", "jscpdCloneHash/v1"
        )

    def test_sarif_needs_exactly_one_jscpd_run_with_results(self) -> None:
        cases = [
            '{"version": "2.1.0", "runs": []}',
            '{"version": "2.1.0", "runs": [{}]}',
            '{"version": "2.1.0", "runs": ['
            '{"tool": {"driver": {"name": "other"}}, "results": []}]}',
            '{"version": "2.1.0", "runs": ['
            '{"tool": {"driver": {"name": "jscpd"}}}]}',
            '{"version": "2.1.0", "runs": ['
            '{"tool": {"driver": {"name": "jscpd"}}, "results": []},'
            '{"tool": {"driver": {"name": "jscpd"}}, "results": []}]}',
        ]
        for report in cases:
            with self.subTest(report=report):
                env = self.clone_env([], fake={})
                sarif_path = self.base / "sarif.json"
                sarif_path.write_text(report, encoding="utf-8")
                self.clone_failure(env, "no completed jscpd run")

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
        unchanged = tomllib.loads(
            self.read_file("quality-gate-clones.toml")
        )["entry"]
        self.assertEqual(unchanged[0]["subject"], "fp1")
        self.assertEqual(unchanged[0]["bound"], 1)
        self.assertNotIn("fp-new", self.read_file("quality-gate-clones.toml"))
        self.assertIn("occurs 2 times", text)
        self.assertIn("prune refused", text)

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
        self.assertIn("no check with adapter 'clones'", text)

    def test_invalid_inventory_blocks_clones(self) -> None:
        self.add_file("mystery.txt", "x\n")
        self.write_config(with_clones())
        self.clone_failure({}, "clones: inventory:", "mystery.txt")

    def test_no_files_in_clone_classes_fails(self) -> None:
        self.write_config(with_clones(classes='["empty"]'))
        self.clone_failure({}, "no files selected")

    def test_expired_entry_no_longer_covers(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])],
            [
                {
                    "fingerprint": "fp1",
                    "expires": "2000-01-01",
                    "reason": "expired exception",
                }
            ],
        )
        self.clone_failure(env, "expired baseline entry", "2000-01-01")

    def test_check_prune_lowers_a_passing_baseline(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])],
            [
                {
                    "fingerprint": "fp1",
                    "bound": 3,
                    "files": ["a.py", "b.py"],
                    "reason": "lower me",
                }
            ],
        )
        result = self.run_qg("check", "--prune", "clones", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        entry = self.single_baseline("fp1", "lower me")
        self.assertEqual(entry["files"], ["a.py", "b.py"])

    def test_check_prune_refuses_while_the_check_fails(self) -> None:
        env = self.clone_env(
            [
                ("fp1", [("a.py", 1, 8), ("b.py", 1, 8)]),
                ("fp1", [("a.py", 1, 8), ("c.py", 1, 8)]),
            ],
            [{"fingerprint": "fp1", "bound": 1, "reason": "only one"}],
        )
        self.add_file("c.py", "print('c')\n")
        before = self.read_file("quality-gate-clones.toml")
        result = self.run_qg("check", "--prune", "clones", env=env)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("prune refused", text)
        self.assertEqual(self.read_file("quality-gate-clones.toml"), before)

    def test_check_prune_unknown_id_exits_2(self) -> None:
        result = self.run_qg("check", "--prune", "mystery")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("unknown check 'mystery'", text)

    def test_invalid_baseline_toml_fails(self) -> None:
        env = self.clone_env([])
        self.add_file("quality-gate-clones.toml", "[clone\n")
        self.clone_failure(env, "invalid baseline")

    def test_invalid_baseline_bound_fails(self) -> None:
        env = self.clone_env([])
        self.add_file(
            "quality-gate-clones.toml",
            '[[entry]]\nsubject = "fp1"\nbound = "high"\n'
            'reason = "never valid"\n',
        )
        self.clone_failure(env, "bound", "finite number")

    def test_non_finite_baseline_bound_fails(self) -> None:
        for value in ("inf", "-inf", "nan"):
            with self.subTest(value=value):
                env = self.clone_env([])
                self.add_file(
                    "quality-gate-clones.toml",
                    f'[[entry]]\nsubject = "fp1"\nbound = {value}\n'
                    'reason = "never valid"\n',
                )
                result, document = self.run_json(env=env)
                self.assertEqual(result.returncode, 1, output(result))
                self.assertNotIn("Infinity", result.stdout)
                self.assertNotIn("NaN", result.stdout)
                self.assertEqual(document["decision"], "rejected")
                check = self.check_by_id(document, "clones")
                self.assertEqual(check["outcome"], "error")
                self.assertIn("finite number", result.stderr)

    def test_zero_count_rejects_an_occurrence(self) -> None:
        env = self.clone_env(
            [("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])],
            [{"fingerprint": "fp1", "count": 0, "reason": "nothing accepted"}],
        )
        self.clone_failure(
            env, "occurs 1 time", "baseline bound 0"
        )

    def test_real_jscpd_reports_elisp_and_bash_clone_pairs(self) -> None:
        self.write_config(
            """\
schema = 1

[code]
patterns = ["*.el", "*.sh"]
shebangs = ["sh", "bash"]

[levels]
required_tiers = [1]

[classes.lisp]
code = true
description = "Emacs Lisp"
checks = ["clones"]

[classes.shell]
code = true
description = "Bash"
checks = ["clones"]

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

[checks.clones]
adapter = "clones"
tier = 1
enforcement = "enforced"
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
