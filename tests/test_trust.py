"""Tests for --policy-from: protected inputs, effective inputs and identity."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import unittest

from support import (
    BASE_CONFIG,
    PYTHON_TEST_HEADER,
    FixtureCase,
    baseline_text,
    output,
    sarif_report,
    with_clones,
)
from test_python_crap import crap_config

CLONE_FILES = ("a.py", "b.py")
CLONES_HEADER = (
    'check = "clones"\nmetric_version = "jscpd-clone-occurrences/1"\n'
)


def with_protect(config: str, *paths: str) -> str:
    values = ", ".join(json.dumps(path) for path in paths)
    return config.replace(
        "[levels]",
        f'[protect]\npaths = [{values}]\n\n[levels]',
    )


def without_protect(config: str) -> str:
    start = config.index("[protect]")
    end = config.index("[levels]")
    return config[:start] + config[end:]


class TrustCase(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        self.fixture_gate()

    def commit_revision(self) -> str:
        self.commit_all()
        return self.git("rev-parse", "HEAD").stdout.strip()

    def trust_json(
        self, revision: str, *args: str, env: dict[str, str] | None = None
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        return self.run_json(
            "--policy-from", revision, *args, env=env
        )

    def protected(
        self, document: dict[str, object], path: str
    ) -> dict[str, object]:
        trust = document["trust"]
        assert isinstance(trust, dict)
        for item in trust["protected"]:
            if item["path"] == path:
                return item
        self.fail(f"no protected entry {path!r}")

    def clone_env(self, count: int = 1) -> dict[str, str]:
        clones = [
            ("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])
            for _index in range(count)
        ]
        return self.install_fake_jscpd(sarif_report(clones))

    def write_clones_baseline(
        self,
        bound: int = 1,
        reason: str = "reviewed mirror",
    ) -> None:
        self.add_file(
            "quality-gate-clones.toml",
            baseline_text(
                [
                    {
                        "subject": "fp1",
                        "bound": bound,
                        "files": list(CLONE_FILES),
                        "reason": reason,
                    }
                ]
            ),
        )

    def empty_clones_baseline(self) -> None:
        self.add_file("quality-gate-clones.toml", CLONES_HEADER)

    def commit_ruff_revision(self) -> str:
        self.write_config(with_protect(BASE_CONFIG, "ruff.toml"))
        self.add_file("ruff.toml", "line-length = 100\n")
        return self.commit_revision()

    def change_ruff(self) -> None:
        self.add_file("ruff.toml", "line-length = 200\n")

    def assert_blocked(
        self,
        result: subprocess.CompletedProcess[str],
        document: dict[str, object],
    ) -> None:
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "blocked")
        self.assertEqual(
            self.protected(document, "ruff.toml")["status"], "blocked"
        )

    def assert_clone_fails_tightened(
        self,
        result: subprocess.CompletedProcess[str],
        document: dict[str, object],
    ) -> None:
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "clones")
        self.assertEqual(check["outcome"], "fail")
        entry = self.protected(document, "quality-gate-clones.toml")
        self.assertEqual(entry["status"], "tightened")


class BaselineTrustTests(TrustCase):
    def setUp(self) -> None:
        super().setUp()
        self.write_config(with_clones())
        self.add_file("b.py", "print('b')\n")

    def test_added_baseline_entry_is_ignored(self) -> None:
        self.empty_clones_baseline()
        revision = self.commit_revision()
        self.add_file(
            "quality-gate-clones.toml",
            CLONES_HEADER
            + '\n[[entry]]\nsubject = "fp1"\nbound = 1\n'
            'reason = "candidate exception"\n',
        )
        result, document = self.trust_json(revision, env=self.clone_env())
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        check = self.check_by_id(document, "clones")
        self.assertEqual(check["outcome"], "fail")
        entry = self.protected(document, "quality-gate-clones.toml")
        self.assertEqual(entry["status"], "ignored")
        self.assertEqual(entry["ignored_entries"], ["fp1"])

    def test_raised_baseline_bound_is_ignored(self) -> None:
        self.write_clones_baseline()
        revision = self.commit_revision()
        self.write_clones_baseline(bound=5)
        result, document = self.trust_json(
            revision, env=self.clone_env(count=2)
        )
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        entry = self.protected(document, "quality-gate-clones.toml")
        self.assertEqual(entry["status"], "ignored")
        self.assertEqual(entry["ignored_entries"], ["fp1"])

    def test_removed_baseline_entry_takes_effect(self) -> None:
        self.write_clones_baseline()
        revision = self.commit_revision()
        self.empty_clones_baseline()
        result, document = self.trust_json(revision, env=self.clone_env())
        self.assert_clone_fails_tightened(result, document)

    def test_lowered_baseline_bound_takes_effect(self) -> None:
        self.write_clones_baseline(bound=5)
        revision = self.commit_revision()
        self.write_clones_baseline(bound=1)
        result, document = self.trust_json(
            revision, env=self.clone_env(count=2)
        )
        self.assert_clone_fails_tightened(result, document)

    def test_prune_writes_revisions_baseline_lowered(self) -> None:
        self.write_clones_baseline(bound=5)
        revision = self.commit_revision()
        self.add_file(
            "quality-gate-clones.toml",
            baseline_text(
                [
                    {
                        "subject": "fp1",
                        "bound": 9,
                        "files": list(CLONE_FILES),
                        "reason": "candidate raised it",
                    },
                    {
                        "subject": "fp2",
                        "bound": 1,
                        "files": list(CLONE_FILES),
                        "reason": "candidate addition",
                    },
                ]
            ),
        )
        result, document = self.trust_json(
            revision, "--prune", "clones", env=self.clone_env()
        )
        self.assertEqual(result.returncode, 0, output(result))
        self.assertTrue(document["prune"]["performed"])
        text = self.read_file("quality-gate-clones.toml")
        self.assertIn('subject = "fp1"', text)
        self.assertIn("bound = 1", text)
        self.assertNotIn("fp2", text)
        self.assertNotIn("bound = 9", text)


class PolicyTrustTests(TrustCase):
    def test_raised_policy_threshold_is_ignored(self) -> None:
        (self.repo / "a.py").unlink()
        self.add_file("pkg/__init__.py", "")
        self.add_file(
            "pkg/new.py",
            "def three(value):\n"
            "    if value:\n"
            "        if value > 1:\n"
            "            return 1\n"
            "    return 2\n",
        )
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER
            + "\nclass Sample(unittest.TestCase):\n"
            "    def test_ok(self):\n"
            "        self.assertTrue(True)\n",
        )
        self.write_config(crap_config())
        revision = self.commit_revision()
        self.write_config(crap_config(threshold=100))
        result, document = self.trust_json(
            revision, env=self.default_tool_env()
        )
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        check = self.check_by_id(document, "crap")
        self.assertEqual(check["outcome"], "fail")
        finding = next(
            item
            for item in check["findings"]
            if item["subject"] == "pkg/new.py:three"
        )
        self.assertEqual(finding["threshold"], 6.0)
        entry = self.protected(document, "quality-gate.toml")
        self.assertEqual(entry["status"], "ignored")

    def test_authorized_policy_replacement_is_used(self) -> None:
        revision = self.commit_revision()
        self.write_config(
            BASE_CONFIG.replace(
                'run = ["python3", "-c", "print(1)"]',
                'run = ["python3", "-c", "import sys; sys.exit(1)"]',
            )
        )
        result, document = self.trust_json(
            revision, "--allow-protected", "quality-gate.toml"
        )
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        check = self.check_by_id(document, "smoke")
        self.assertEqual(check["outcome"], "fail")
        entry = self.protected(document, "quality-gate.toml")
        self.assertEqual(entry["status"], "authorized")

    def test_removed_check_is_ignored(self) -> None:
        revision = self.commit_revision()
        self.write_config(
            BASE_CONFIG.replace('checks = ["smoke"]\n', "") + "\n"
        )
        result, document = self.trust_json(revision)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["decision"], "accepted")
        check = self.check_by_id(document, "smoke")
        self.assertEqual(check["outcome"], "pass")
        entry = self.protected(document, "quality-gate.toml")
        self.assertEqual(entry["status"], "ignored")

    def test_unauthorized_protected_change_is_blocked(self) -> None:
        revision = self.commit_ruff_revision()
        self.change_ruff()
        result, document = self.trust_json(revision)
        self.assert_blocked(result, document)
        self.assertIn("ruff.toml", result.stderr)

    def test_authorized_protected_change_passes(self) -> None:
        revision = self.commit_ruff_revision()
        self.change_ruff()
        result, document = self.trust_json(
            revision, "--allow-protected", "ruff.toml"
        )
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["decision"], "accepted")
        self.assertEqual(
            self.protected(document, "ruff.toml")["status"], "authorized"
        )

    def test_protected_glob_blocks_a_change(self) -> None:
        self.write_config(with_protect(BASE_CONFIG, "*.md"))
        revision = self.commit_revision()
        self.add_file("README.md", "# changed\n")
        result, document = self.trust_json(revision)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "blocked")
        entry = self.protected(document, "README.md")
        self.assertEqual(entry["status"], "blocked")

    def test_deleted_protect_entry_still_protects(self) -> None:
        revision = self.commit_ruff_revision()
        self.write_config(
            without_protect(with_protect(BASE_CONFIG, "ruff.toml"))
        )
        self.change_ruff()
        result, document = self.trust_json(revision)
        self.assert_blocked(result, document)


class IdentityTrustTests(TrustCase):
    def test_protected_file_changed_during_the_run_is_error(self) -> None:
        writer = (
            "import pathlib; "
            "pathlib.Path('ruff.toml').write_text('line-length = 200\\n'); "
            "print(1)"
        )
        self.write_config(
            with_protect(BASE_CONFIG, "ruff.toml").replace(
                'run = ["python3", "-c", "print(1)"]',
                f'run = [{json.dumps(sys.executable)}, "-c", '
                f'{json.dumps(writer)}]',
            )
        )
        self.add_file("ruff.toml", "line-length = 100\n")
        revision = self.commit_revision()
        result, document = self.trust_json(revision)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertIn("ruff.toml", document["error"])
        self.assertIn("changed during the run", document["error"])
        trust = document["trust"]
        self.assertNotEqual(
            trust["identity_before"]["protected"]["ruff.toml"][
                "candidate_sha256"
            ],
            trust["identity_after"]["protected"]["ruff.toml"][
                "candidate_sha256"
            ],
        )

    def test_missing_revision_exits_two(self) -> None:
        result = self.run_qg("check", "--policy-from", "deadbeef")
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("deadbeef", result.stderr)

    def test_gate_inside_candidate_is_refused(self) -> None:
        revision = self.commit_revision()
        inside = self.repo / "gatecopy"
        shutil.copytree(self.gate, inside)
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(inside / "qg.py"),
                "--repo",
                str(self.repo),
                "check",
                "--policy-from",
                revision,
            ],
            cwd=str(self.repo),
            env=self.env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn(str(inside), result.stderr)
        self.assertIn(str(self.repo), result.stderr)

    def test_trust_object_records_identity(self) -> None:
        revision = self.commit_revision()
        result, document = self.trust_json(revision)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["schema"], 3)
        trust = document["trust"]
        self.assertEqual(trust["policy_from"], revision)
        paths = {item["path"] for item in trust["protected"]}
        self.assertIn("quality-gate.toml", paths)
        self.assertIn("tools.lock.toml", paths)
        for item in trust["protected"]:
            self.assertTrue(
                {"path", "rev_sha256", "candidate_sha256", "status"}
                <= set(item)
            )
        self.assertEqual(
            trust["identity_before"], trust["identity_after"]
        )
        self.assertEqual(
            trust["identity_before"]["revision"], revision
        )
        self.assertIn("tools", trust["identity_before"])
        self.assertIn("gate", trust["identity_before"])

    def test_candidate_tools_lock_change_is_ignored(self) -> None:
        lock = (self.gate / "tools.lock.toml").read_text(encoding="utf-8")
        self.add_file("tools.lock.toml", lock)
        revision = self.commit_revision()
        changed = lock.replace(
            "b44982df629d97a4c8fc703ff27f73437e1bc1e683fb11862b56d486e6857ff8",
            "0" * 64,
        )
        self.assertNotEqual(lock, changed)
        self.add_file("tools.lock.toml", changed)
        result, document = self.trust_json(revision)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["decision"], "accepted")
        entry = self.protected(document, "tools.lock.toml")
        self.assertEqual(entry["status"], "ignored")

    def test_allow_protected_without_policy_from_exits_two(self) -> None:
        result = self.run_qg("check", "--allow-protected", "ruff.toml")
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("--policy-from", result.stderr)


if __name__ == "__main__":
    unittest.main()
