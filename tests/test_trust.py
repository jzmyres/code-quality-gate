"""Tests for --policy-from: protected inputs, effective inputs and identity."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
from dataclasses import replace

from support import (
    BASE_CONFIG,
    GATE,
    PYTHON_TEST_HEADER,
    FixtureCase,
    baseline_text,
    output,
    sarif_report,
    with_clones,
)
from test_python_crap import crap_config

from quality_gate import trust
from quality_gate.policy import load_config
from quality_gate.trust import prepare_trust

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

    def merge_attack(self, check: str, forged: str) -> str:
        """Candidate code overwrites the historical merged-baseline path."""
        name = hashlib.sha256(f"merged\0{check}".encode()).hexdigest()[:16]
        return (
            "        import os, pathlib, tempfile\n"
            "        for directory in pathlib.Path(tempfile.gettempdir()).glob('qg-merge-*'):\n"
            f"            (directory / {name + '.toml'!r}).write_text({forged!r})\n"
            "            pathlib.Path(os.environ['QG_ATTACK_MARKER']).write_text('written')\n"
            "        self.assertTrue(True)\n"
        )

    def attack_env(self) -> dict[str, str]:
        temporary = self.base / "attack-temp"
        temporary.mkdir(exist_ok=True)
        env = self.default_tool_env()
        env.update({
            "TMPDIR": str(temporary),
            "QG_ATTACK_MARKER": str(self.base / "attack-marker"),
        })
        return env

    def attacked_check(self, revision: str, name: str) -> dict[str, object]:
        result, document = self.trust_json(revision, env=self.attack_env())
        self.assertTrue((self.base / "attack-marker").exists(), output(result))
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        return self.check_by_id(document, name)

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

    def test_malformed_candidate_baseline_keeps_trusted_entries(self) -> None:
        self.write_clones_baseline(bound=5)
        revision = self.commit_revision()
        self.add_file("quality-gate-clones.toml", "not = [valid\n")
        result, document = self.trust_json(revision, env=self.clone_env())
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("candidate baseline ignored", result.stderr)
        entry = self.protected(document, "quality-gate-clones.toml")
        self.assertEqual(entry["status"], "ignored")
        self.assertEqual(entry["ignored_entries"], [])
        self.assertTrue(self.check_by_id(document, "clones")["satisfied"])

    def test_changed_effective_baseline_fails_identity_before_prune(self) -> None:
        self.write_clones_baseline()
        revision = self.commit_revision()
        trust = prepare_trust(self.repo, revision, [])
        self.addCleanup(trust.close)
        check = trust.config.checks["clones"]
        self.assertIsNotNone(check.effective_baseline)
        entry = check.effective_baseline[0]
        trust.config.checks["clones"] = replace(
            check, effective_baseline=(replace(entry, bound=99),)
        )
        refusal = trust.before_prune()
        self.assertIn(
            "effective input baseline quality-gate-clones.toml", refusal
        )
        key = "baseline quality-gate-clones.toml"
        self.assertNotEqual(
            trust.identity_before["effective_inputs"][key],
            trust.identity_after_checks["effective_inputs"][key],
        )

    def test_prune_through_a_symlinked_parent_is_refused(self) -> None:
        self.write_config(with_clones(baseline="cfg/clones.toml"))
        self.add_file(
            "cfg/clones.toml",
            baseline_text(
                [
                    {
                        "subject": "fp1",
                        "bound": 5,
                        "files": list(CLONE_FILES),
                        "reason": "reviewed mirror",
                    }
                ]
            ),
        )
        revision = self.commit_revision()
        outside = self.base / "outside"
        outside.mkdir()
        target = outside / "clones.toml"
        (self.repo / "cfg" / "clones.toml").replace(target)
        (self.repo / "cfg").rmdir()
        (self.repo / "cfg").symlink_to(outside)
        before = target.read_text(encoding="utf-8")
        result, _document = self.trust_json(
            revision, "--prune", "clones", env=self.clone_env()
        )
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("cfg/clones.toml", result.stderr)
        self.assertEqual(target.read_text(encoding="utf-8"), before)

    def test_prune_refuses_a_parent_symlinked_during_the_run(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        sentinel = outside / "clones.toml"
        sentinel.write_text("sentinel\n", encoding="utf-8")
        writer = (
            "import pathlib, shutil; "
            "shutil.rmtree('cfg'); "
            f"pathlib.Path('cfg').symlink_to({str(outside)!r}); "
            "print(1)"
        )
        self.write_config(
            with_clones(baseline="cfg/clones.toml").replace(
                'run = ["python3", "-c", "print(1)"]',
                f'run = [{json.dumps(sys.executable)}, "-c", '
                f'{json.dumps(writer)}]',
            )
        )
        self.add_file(
            "cfg/clones.toml",
            baseline_text(
                [
                    {
                        "subject": "fp1",
                        "bound": 5,
                        "files": list(CLONE_FILES),
                        "reason": "reviewed mirror",
                    }
                ]
            ),
        )
        revision = self.commit_revision()
        result, document = self.trust_json(
            revision, "--prune", "clones", env=self.clone_env()
        )
        self.assertEqual(result.returncode, 2, output(result))
        self.assertFalse(document["prune"]["performed"])
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "sentinel\n")

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

    def test_candidate_test_cannot_raise_merged_crap_baseline(self) -> None:
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
        entry = {"subject": "pkg/new.py:three", "bound": 8, "reason": "reviewed"}
        trusted = baseline_text(
            [entry], check="crap", metric_version="python-lines/1"
        )
        forged = baseline_text(
            [{**entry, "bound": 100}], check="crap", metric_version="python-lines/1"
        )
        self.write_config(crap_config())
        self.add_file("quality-gate-crap.toml", trusted)
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER + "\nclass Sample(unittest.TestCase):\n"
            "    def test_attack(self):\n"
            + self.merge_attack("crap", forged),
        )
        revision = self.commit_revision()
        check = self.attacked_check(revision, "crap")
        finding = next(
            item for item in check["findings"]
            if item["subject"] == "pkg/new.py:three"
        )
        self.assertEqual(finding["value"], 12)
        self.assertEqual(finding["bound"], 8)
        self.assertTrue(finding["blocking"])

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

    def test_replacement_ref_cannot_change_the_policy(self) -> None:
        failing = BASE_CONFIG.replace(
            'run = ["python3", "-c", "print(1)"]',
            'run = ["python3", "-c", "import sys; sys.exit(1)"]',
        )
        self.write_config(failing)
        revision = self.commit_revision()
        self.write_config(BASE_CONFIG)
        self.commit_all()
        replacement = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("replace", revision, replacement)
        result, document = self.trust_json(revision)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertEqual(
            self.check_by_id(document, "smoke")["outcome"], "fail"
        )

    def test_graft_file_is_refused(self) -> None:
        revision = self.commit_revision()
        info = self.repo / ".git" / "info"
        info.mkdir(exist_ok=True)
        graft = info / "grafts"
        graft.write_text("", encoding="utf-8")
        result = self.run_qg("check", "--policy-from", revision)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn(str(graft), result.stderr)

    def test_protected_symlink_is_refused(self) -> None:
        revision = self.commit_ruff_revision()
        target = self.base / "outside.toml"
        target.write_text("line-length = 200\n", encoding="utf-8")
        (self.repo / "ruff.toml").unlink()
        (self.repo / "ruff.toml").symlink_to(target)
        result = self.run_qg("check", "--policy-from", revision)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("ruff.toml", result.stderr)

    def test_protected_fifo_is_refused_without_blocking(self) -> None:
        revision = self.commit_ruff_revision()
        (self.repo / "ruff.toml").unlink()
        os.mkfifo(self.repo / "ruff.toml")
        started = time.monotonic()
        result = self.run_qg(
            "check", "--policy-from", revision, timeout=5
        )
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("ruff.toml", result.stderr)
        self.assertLess(elapsed, 5)

    def test_protected_symlinked_parent_is_refused(self) -> None:
        self.write_config(with_protect(BASE_CONFIG, "cfg/ruff.toml"))
        self.add_file("cfg/ruff.toml", "line-length = 100\n")
        revision = self.commit_revision()
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "ruff.toml").write_text(
            "line-length = 200\n", encoding="utf-8"
        )
        (self.repo / "cfg" / "ruff.toml").unlink()
        (self.repo / "cfg").rmdir()
        (self.repo / "cfg").symlink_to(outside)
        result = self.run_qg("check", "--policy-from", revision)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("cfg/ruff.toml", result.stderr)

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


class IdentityDecisionTests(unittest.TestCase):
    def test_trust_identity_comparison_detects_only_changed_gate_and_tool_files(self) -> None:
        before = {
            "tools": {"ruff": {"payload_sha256": "old"}},
            "gate": {"files": {"qg.py": "old", "unchanged.py": "same"}},
        }
        after = {
            "tools": {"ruff": {"payload_sha256": "new"}},
            "gate": {"files": {"qg.py": "new", "unchanged.py": "same"}},
        }
        self.assertEqual(trust._identity_problems(before, before), [])
        self.assertEqual(
            trust._identity_problems(before, after),
            ["tool payload ruff changed during the run", "gate file qg.py changed during the run"],
        )

    def test_trust_prune_identity_allows_only_the_exact_generated_bytes(self) -> None:
        before = {"rev_sha256": "revision", "candidate_sha256": "old"}
        written = b"trusted, tightened baseline"
        after = {"rev_sha256": "revision", "candidate_sha256": trust._sha256(written)}
        other = {"rev_sha256": "revision", "candidate_sha256": trust._sha256(b"altered")}
        self.assertTrue(trust._allowed_change(before, after, written))
        self.assertFalse(trust._allowed_change(before, other, written))
        self.assertFalse(trust._allowed_change(before, {**after, "rev_sha256": "changed"}, written))


class IdentityTrustTests(TrustCase):
    def test_temporary_lock_rewrite_cannot_change_tool_pins(self) -> None:
        self.add_file(
            "tools.lock.toml", (self.gate / "tools.lock.toml").read_bytes()
        )
        modify = (
            "import pathlib, tempfile; "
            "path = next(pathlib.Path(tempfile.gettempdir()).glob('qg-merge-*/rev-tools.lock.toml')); "
            "path.with_suffix('.saved').write_bytes(path.read_bytes()); "
            "path.write_text(path.read_text().replace('[ruff]', '[untrusted]')); "
            "print(1)"
        )
        restore = (
            "import pathlib, tempfile; "
            "path = next(pathlib.Path(tempfile.gettempdir()).glob('qg-merge-*/rev-tools.lock.toml')); "
            "path.write_bytes(path.with_suffix('.saved').read_bytes())"
        )
        config = BASE_CONFIG.replace(
            'run = ["python3", "-c", "print(1)"]',
            f'run = [{json.dumps(sys.executable)}, "-c", {json.dumps(modify)}]',
        )
        config += (
            '\n[checks.tool]\nadapter = "command"\ntier = 1\n'
            'enforcement = "enforced"\nrun = ["{tool:ruff}", "--version"]\n'
            '\n[checks.restore]\nadapter = "command"\ntier = 1\n'
            'enforcement = "enforced"\n'
            f'run = [{json.dumps(sys.executable)}, "-c", {json.dumps(restore)}]\n'
        )
        self.write_config(config)
        revision = self.commit_revision()
        result, document = self.trust_json(revision, env=self.attack_env())
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.check_by_id(document, "tool")["outcome"], "pass")
        self.assertEqual(
            document["trust"]["identity_before"],
            document["trust"]["identity_after"],
        )

    def test_effective_tool_lock_changed_during_the_run_is_error(self) -> None:
        self.add_file(
            "tools.lock.toml", (self.gate / "tools.lock.toml").read_bytes()
        )
        writer = (
            "import pathlib, tempfile; "
            "paths = list(pathlib.Path(tempfile.gettempdir()).glob('qg-merge-*/rev-tools.lock.toml')); "
            "assert paths; "
            "paths[0].write_text(paths[0].read_text() + '\\n# changed\\n'); "
            "print(1)"
        )
        self.write_config(
            BASE_CONFIG.replace(
                'run = ["python3", "-c", "print(1)"]',
                f'run = [{json.dumps(sys.executable)}, "-c", {json.dumps(writer)}]',
            )
        )
        revision = self.commit_revision()
        result, document = self.trust_json(revision, env=self.attack_env())
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertIn("effective input tool lock", document["error"])
        self.assertIn("tools.lock.toml", document["error"])
        before = document["trust"]["identity_before"]["effective_inputs"]
        after = document["trust"]["identity_after"]["effective_inputs"]
        self.assertNotEqual(
            before["tool lock tools.lock.toml"], after["tool lock tools.lock.toml"]
        )

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

    def test_protected_file_created_during_the_run_is_error(self) -> None:
        writer = (
            "import pathlib; "
            "pathlib.Path('generated').mkdir(); "
            "pathlib.Path('generated/new.txt').write_text('x\\n'); "
            "print(1)"
        )
        self.add_file(".gitignore", "__pycache__/\ngenerated/\n")
        self.write_config(
            with_protect(BASE_CONFIG, "generated/*.txt").replace(
                'run = ["python3", "-c", "print(1)"]',
                f'run = [{json.dumps(sys.executable)}, "-c", '
                f'{json.dumps(writer)}]',
            )
        )
        revision = self.commit_revision()
        result, document = self.trust_json(revision)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertIn("generated/new.txt", document["error"])
        trust = document["trust"]
        self.assertNotIn(
            "generated/new.txt", trust["identity_before"]["protected"]
        )
        self.assertIn(
            "generated/new.txt", trust["identity_after"]["protected"]
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


class GitInvocationTests(TrustCase):
    def test_configured_fsmonitor_never_runs(self) -> None:
        revision = self.commit_revision()
        marker = self.base / "fsmonitor-ran"
        program = self.base / "fsmonitor.sh"
        program.write_text(
            "#!/bin/sh\n"
            f"printf ran >> {json.dumps(str(marker))}\n",
            encoding="utf-8",
        )
        program.chmod(0o755)
        self.git("config", "core.fsmonitor", str(program))
        result, _document = self.trust_json(revision)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse(marker.exists(), "configured fsmonitor ran")
        result = self.run_qg("check")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse(marker.exists(), "configured fsmonitor ran")


class RepositoryPolicyTests(TrustCase):
    def repository_config(self) -> str:
        real = load_config(GATE)
        run = list(real.checks["ruff"].spec.run)
        self.assertIn("--config", run)
        self.assertEqual(run[run.index("--config") + 1], "ruff.toml")
        lines = [
            line
            for line in BASE_CONFIG.splitlines()
            if not line.startswith("tests_pattern = ")
        ]
        config = "\n".join(lines).replace(
            'run = ["python3", "-c", "print(1)"]',
            f"run = {json.dumps(run)}",
        )
        config = config.replace(
            'checks = ["smoke"]', 'checks = ["smoke", "count"]'
        )
        count_run = json.dumps(
            ["python3", "-c", "print('Ran 1 test in 0.01s')"]
        )
        count = (
            "\n[checks.count]\n"
            'adapter = "command"\n'
            "tier = 1\n"
            'enforcement = "enforced"\n'
            f"run = {count_run}\n"
            f"tests_pattern = {json.dumps('^Ran ([0-9]+) tests? in')}\n"
        )
        return with_protect(config, *real.protect_paths) + count

    def test_candidate_ruff_configuration_is_refused(self) -> None:
        real = load_config(GATE)
        self.assertIn("ruff.toml", real.protect_paths)
        ruff_config = (GATE / "ruff.toml").read_text(encoding="utf-8")
        self.add_file("ruff.toml", ruff_config)
        self.add_file("a.py", "import os\n")
        self.write_config(self.repository_config())
        revision = self.commit_revision()
        self.add_file("ruff.toml", ruff_config + 'ignore = ["F401"]\n')
        result, document = self.trust_json(
            revision, env=self.default_tool_env()
        )
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "blocked")
        self.assertEqual(
            self.protected(document, "ruff.toml")["status"], "blocked"
        )
        self.assertEqual(
            self.check_by_id(document, "smoke")["outcome"],
            "pass",
            json.dumps(self.check_by_id(document, "smoke"), indent=2),
        )


if __name__ == "__main__":
    unittest.main()
