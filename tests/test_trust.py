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
import zlib
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
from test_adapters import FLOOR_CONFIG, FLOOR_STUB
from test_python_crap import crap_config

from quality_gate import adapters, ratchet, trust
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

    def directory_revision(self) -> str:
        return str(self.trusted_directory(self.commit_revision()))

    def trusted_ruff_directory(self) -> str:
        return str(self.trusted_directory(self.commit_ruff_revision()))

    def forge(self, oid: str, kind: str, content: bytes) -> None:
        """Replace the loose object at oid, keeping its file name."""
        path = self.repo / ".git" / "objects" / oid[:2] / oid[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            path.chmod(0o644)
        header = f"{kind} {len(content)}".encode("ascii") + b"\0"
        path.write_bytes(zlib.compress(header + content))

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

    def assert_inventory_block_report(self, revision: str, *details: str) -> None:
        check = self.run_qg("check", "--policy-from", revision)
        self.assertEqual(check.returncode, 1, output(check))
        reported_details = [
            line for line in check.stderr.splitlines()
            if line.startswith("check: protected input ") and line.endswith("; blocked")
        ]
        self.assertEqual(reported_details, list(details), output(check))
        summary = next(
            line for line in check.stderr.splitlines()
            if line.startswith("check: blocked:")
        )
        for selection in ((), ("--list", "python")):
            with self.subTest(selection=selection):
                inventory = self.run_qg(
                    "inventory", *selection, "--policy-from", revision
                )
                self.assertEqual(inventory.returncode, 1, output(inventory))
                self.assertEqual(inventory.stdout, "")
                lines = [line for line in inventory.stderr.splitlines() if line.startswith("check:")]
                self.assertEqual(lines, [*details, summary])

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
        revision = self.directory_revision()
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
        revision = self.directory_revision()
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
        revision = self.directory_revision()
        self.empty_clones_baseline()
        result, document = self.trust_json(revision, env=self.clone_env())
        self.assert_clone_fails_tightened(result, document)

    def test_lowered_baseline_bound_takes_effect(self) -> None:
        self.write_clones_baseline(bound=5)
        revision = self.directory_revision()
        self.write_clones_baseline(bound=1)
        result, document = self.trust_json(
            revision, env=self.clone_env(count=2)
        )
        self.assert_clone_fails_tightened(result, document)

    def test_malformed_candidate_baseline_keeps_trusted_entries(self) -> None:
        self.write_clones_baseline(bound=5)
        revision = self.directory_revision()
        self.add_file("quality-gate-clones.toml", "not = [valid\n")
        result, document = self.trust_json(revision, env=self.clone_env())
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("candidate baseline ignored", result.stderr)
        entry = self.protected(document, "quality-gate-clones.toml")
        self.assertEqual(entry["status"], "ignored")
        self.assertEqual(entry["ignored_entries"], [])
        self.assertTrue(self.check_by_id(document, "clones")["satisfied"])


class PruneTrustRefusalTests(TrustCase):
    def candidate_files(self) -> dict[str, bytes]:
        return {
            path.relative_to(self.repo).as_posix(): path.read_bytes()
            for path in self.repo.rglob("*")
            if path.is_file()
            and ".git" not in path.relative_to(self.repo).parts
        }

    def test_prune_with_policy_from_is_a_usage_error(self) -> None:
        self.write_config(with_clones())
        self.write_clones_baseline(bound=5)
        revision = self.directory_revision()
        before = self.candidate_files()
        result = self.run_qg(
            "check",
            "--prune",
            "clones",
            "--policy-from",
            revision,
            env=self.clone_env(),
        )
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("--prune", result.stderr)
        self.assertIn("--policy-from", result.stderr)
        self.assertNotIn("check: inventory", result.stderr + result.stdout)
        self.assertEqual(self.candidate_files(), before)


class StubFloorTrustTests(TrustCase):
    def setUp(self) -> None:
        super().setUp()
        adapters.register_adapter(FLOOR_STUB)
        self.addCleanup(adapters.remove_adapter, FLOOR_STUB.name)
        self.write_config(FLOOR_CONFIG.replace(
            'enforcement = "enforced"', 'enforcement = "enforced"\ndirection = "max"',
        ))
        self.add_file(
            "floor.toml",
            baseline_text(
                [{
                    "subject": "floor-subject",
                    "bound": 4,
                    "reason": "reviewed floor",
                }],
                check="floor",
                metric_version="stub/1",
            ),
        )
        self.directory = self.directory_revision()
        self.add_file(
            "floor.toml",
            baseline_text([], check="floor", metric_version="stub/1"),
        )

    def assert_floor_retained(self, prepared: trust.Trust) -> None:
        entries = prepared.config.checks["floor"].effective_baseline
        self.assertEqual(
            [(entry.subject, entry.bound, entry.direction) for entry in entries],
            [("floor-subject", 4, "min")],
        )
        item = next(
            item for item in prepared.protected if item.path == "floor.toml"
        )
        self.assertEqual(item.status, "ignored")
        self.assertEqual(item.ignored_entries, ("floor-subject",))

    def test_candidate_omitting_a_floor_keeps_the_trusted_bound(self) -> None:
        self.assertIs(adapters.adapter_for(FLOOR_STUB.name), FLOOR_STUB)
        prepared = prepare_trust(self.repo, self.directory, [])
        self.addCleanup(prepared.close)
        self.assert_floor_retained(prepared)

    def test_all_minimum_kinds_keep_floor_with_max_configured_default(self) -> None:
        descriptor = replace(
            FLOOR_STUB,
            default_direction="min",
            entry_direction=lambda _subject, _configured: "min",
        )
        adapters.register_adapter(descriptor)
        prepared = prepare_trust(self.repo, self.directory, [])
        self.addCleanup(prepared.close)
        check = prepared.config.checks["floor"]
        self.assertEqual(check.direction, "max")
        self.assert_floor_retained(prepared)
        entries = check.effective_baseline
        for value, satisfied in ((3, False), (4, True), (5, True)):
            with self.subTest(value=value):
                result = ratchet.evaluate(
                    [ratchet.Finding("floor-subject", value, "file:1", kind="floor")],
                    entries,
                    threshold=0,
                    enforcement="enforced",
                    prefix="check: floor",
                    adapter=descriptor,
                    domain=ratchet.Domain.all(),
                    direction=check.direction,
                )
                self.assertEqual(result.entries[0].direction, "min")
                self.assertEqual(result.findings[0].direction, "min")
                self.assertEqual(result.satisfied, satisfied)
                if satisfied:
                    self.assertEqual(ratchet.pruned_entries(result)[0].bound, value)


class PolicyTrustTests(TrustCase):
    def test_historical_package_lock_remains_usable(self) -> None:
        lock = (
            '[legacy]\nversion = "1"\nurl = "file:///unused"\n'
            f'sha256 = "{"0" * 64}"\npayload_sha256 = "{"0" * 64}"\n'
            'format = "deb"\nbinary = "usr/bin/legacy"\n'
        )
        self.add_file("tools.lock.toml", lock)
        revision = self.directory_revision()
        self.add_file("tools.lock.toml", "")
        result, document = self.trust_json(revision)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.protected(document, "tools.lock.toml")["status"], "ignored")
        self.assertEqual(document["trust"]["identity_before"]["tools"]["legacy"]["version"], "1")

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
        revision = self.directory_revision()
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
        revision = self.directory_revision()
        check = self.attacked_check(revision, "crap")
        finding = next(
            item for item in check["findings"]
            if item["subject"] == "pkg/new.py:three"
        )
        self.assertEqual(finding["value"], 12)
        self.assertEqual(finding["bound"], 8)
        self.assertTrue(finding["blocking"])

    def test_authorized_policy_replacement_is_used(self) -> None:
        revision = self.directory_revision()
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

    def test_protected_symlink_is_refused(self) -> None:
        revision = self.trusted_ruff_directory()
        target = self.base / "outside.toml"
        target.write_text("line-length = 200\n", encoding="utf-8")
        (self.repo / "ruff.toml").unlink()
        (self.repo / "ruff.toml").symlink_to(target)
        result = self.run_qg("check", "--policy-from", revision)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("ruff.toml", result.stderr)

    def test_protected_fifo_is_refused_without_blocking(self) -> None:
        revision = self.trusted_ruff_directory()
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
        revision = self.directory_revision()
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
        revision = self.directory_revision()
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
        revision = self.trusted_ruff_directory()
        self.change_ruff()
        result, document = self.trust_json(revision)
        self.assert_blocked(result, document)
        self.assertIn("ruff.toml", result.stderr)

    def test_changed_protected_file_blocks_inventory_with_check_report(self) -> None:
        revision = self.trusted_ruff_directory()
        self.change_ruff()
        old = hashlib.sha256(b"line-length = 100\n").hexdigest()
        new = hashlib.sha256(b"line-length = 200\n").hexdigest()
        detail = (
            f"check: protected input ruff.toml: REV file {old}; "
            f"candidate file {new}; blocked"
        )
        self.assert_inventory_block_report(revision, detail)

    def test_inventory_reports_missing_protected_file_sides(self) -> None:
        self.write_config(with_protect(BASE_CONFIG, "ruff.toml", "new.toml"))
        self.add_file("ruff.toml", "trusted\n")
        revision = self.directory_revision()
        (self.repo / "ruff.toml").unlink()
        self.add_file("new.toml", "candidate\n")
        old = hashlib.sha256(b"trusted\n").hexdigest()
        new = hashlib.sha256(b"candidate\n").hexdigest()
        details = [
            f"check: protected input new.toml: REV missing -; candidate file {new}; blocked",
            f"check: protected input ruff.toml: REV file {old}; candidate missing -; blocked",
        ]
        self.assert_inventory_block_report(revision, *details)

    def test_authorized_protected_change_passes(self) -> None:
        revision = self.trusted_ruff_directory()
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
        revision = self.directory_revision()
        self.add_file("README.md", "# changed\n")
        result, document = self.trust_json(revision)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "blocked")
        entry = self.protected(document, "README.md")
        self.assertEqual(entry["status"], "blocked")

    def test_deleted_protect_entry_still_protects(self) -> None:
        revision = self.trusted_ruff_directory()
        self.write_config(
            without_protect(with_protect(BASE_CONFIG, "ruff.toml"))
        )
        self.change_ruff()
        result, document = self.trust_json(revision)
        self.assert_blocked(result, document)


class DirectoryTrustTests(TrustCase):
    def test_loosened_baseline_is_rejected(self) -> None:
        self.write_config(with_clones())
        self.add_file("b.py", "print('b')\n")
        self.write_clones_baseline(bound=5)
        directory = self.directory_revision()
        self.write_clones_baseline(bound=1)
        env = self.clone_env(count=2)
        result, document = self.trust_json(directory, env=env)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertEqual(document["trust"]["path"], directory)
        self.assertRegex(document["trust"]["digest"], r"^[0-9a-f]{64}$")
        repeat, repeat_document = self.trust_json(directory, env=env)
        self.assertEqual(
            repeat_document["trust"]["digest"],
            document["trust"]["digest"],
            output(repeat),
        )

    def test_protected_file_is_blocked_or_authorized(self) -> None:
        directory = self.trusted_ruff_directory()
        self.change_ruff()
        result, document = self.trust_json(directory)
        self.assert_blocked(result, document)
        authorized, authorized_document = self.trust_json(
            directory, "--allow-protected", "ruff.toml"
        )
        self.assertEqual(authorized.returncode, 0, output(authorized))
        self.assertEqual(authorized_document["decision"], "accepted")
        self.assertEqual(
            self.protected(authorized_document, "ruff.toml")["status"],
            "authorized",
        )

    def test_directory_glob_skips_symlinks_inside_the_copy(self) -> None:
        self.write_config(with_protect(BASE_CONFIG, "*.md"))
        revision = self.commit_revision()
        directory = self.trusted_directory(revision)
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "linked.md").write_text("# outside\n", encoding="utf-8")
        (directory / "linked.md").symlink_to(outside / "linked.md")
        (directory / "linked").symlink_to(outside, target_is_directory=True)
        self.add_file("README.md", "# changed\n")
        result, document = self.trust_json(str(directory))
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "blocked")
        self.assertEqual(
            self.protected(document, "README.md")["status"], "blocked"
        )

    def test_directory_ignores_replaced_objects_in_the_candidate_store(self) -> None:
        revision = self.commit_revision()
        directory = self.trusted_directory(revision)
        failing = BASE_CONFIG.replace(
            'run = ["python3", "-c", "print(1)"]',
            'run = ["python3", "-c", "import sys; sys.exit(1)"]',
        )
        oid = self.git(
            "rev-parse", f"{revision}:quality-gate.toml"
        ).stdout.strip()
        self.forge(oid, "blob", failing.encode("utf-8"))
        result, document = self.trust_json(str(directory))
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["decision"], "accepted")
        self.assertEqual(self.check_by_id(document, "smoke")["outcome"], "pass")

    def test_inventory_reads_the_directory(self) -> None:
        revision = self.commit_revision()
        directory = self.trusted_directory(revision)
        result = self.run_qg(
            "inventory", "--list", "python", "--policy-from", str(directory)
        )
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("a.py", result.stdout.splitlines())

    def test_directory_inside_candidate_is_refused(self) -> None:
        inside = self.repo / "trusted"
        inside.mkdir()
        (inside / "quality-gate.toml").write_text(
            BASE_CONFIG, encoding="utf-8"
        )
        result = self.run_qg("check", "--policy-from", str(inside))
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn(str(inside), result.stderr)
        self.assertIn("candidate root", result.stderr)

    def test_missing_directory_is_refused(self) -> None:
        missing = self.base / "missing-trusted"
        result = self.run_qg("check", "--policy-from", str(missing))
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn(str(missing), result.stderr)
        self.assertIn("expected an existing directory", result.stderr)

    def test_relative_policy_from_is_refused(self) -> None:
        result = self.run_qg("check", "--policy-from", "trusted")
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("trusted", result.stderr)
        self.assertIn("absolute trusted directory", result.stderr)

    def test_head_as_policy_from_is_refused(self) -> None:
        result = self.run_qg("check", "--policy-from", "HEAD")
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("HEAD", result.stderr)
        self.assertIn("absolute trusted directory", result.stderr)

    def test_commit_id_as_policy_from_is_refused(self) -> None:
        revision = self.commit_revision()
        result = self.run_qg("check", "--policy-from", revision)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn(revision, result.stderr)
        self.assertIn("absolute trusted directory", result.stderr)

    def test_removed_option_is_unknown(self) -> None:
        option = "--changed" + "-from"
        result = self.run_qg("check", option, "HEAD")
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn(option, result.stderr)

    def test_symlink_inside_directory_is_not_followed(self) -> None:
        revision = self.commit_revision()
        directory = self.trusted_directory(revision)
        target = self.base / "outside-policy.toml"
        target.write_text(BASE_CONFIG, encoding="utf-8")
        (directory / "quality-gate.toml").unlink()
        (directory / "quality-gate.toml").symlink_to(target)
        result = self.run_qg("check", "--policy-from", str(directory))
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("quality-gate.toml", result.stderr)
        self.assertIn("missing", result.stderr)


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

    def test_removed_minimum_entry_keeps_the_revision_floor(self) -> None:
        floor = ratchet.BaselineEntry(
            "stub-subject", 4, "reviewed floor", direction="min"
        )
        merged, ignored, tightened = trust._merge_entries([floor], [])
        self.assertEqual(merged, [floor])
        self.assertEqual(ignored, ("stub-subject",))
        self.assertFalse(tightened)


class IdentityTrustTests(TrustCase):
    def gate_identity_with_files(
        self, paths: tuple[str, ...], content: bytes
    ) -> dict[str, object]:
        for relative in paths:
            path = self.gate / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        revision = self.directory_revision()
        self.fixture_runner = lambda: self.gate / "qg.py"
        result = self.run_qg_process(
            "check", "--json", "--policy-from", revision
        )
        document = self.parse_json(result)
        self.assertEqual(result.returncode, 0, output(result))
        return document["trust"]

    def test_gate_new_extension_files_appear_in_identity_with_digests(self) -> None:
        content = b"echo helper\n"
        paths = (
            "quality_gate/helpers/helper.sh",
            "quality_gate/helpers/data",
            "quality_gate/helpers/.settings",
            "quality_gate/helpers/__pycache__",
        )
        identity = self.gate_identity_with_files(paths, content)
        for snapshot in ("identity_before", "identity_after"):
            files = identity[snapshot]["gate"]["files"]
            for relative in paths:
                with self.subTest(snapshot=snapshot, path=relative):
                    self.assertIn(relative, files)
                    self.assertEqual(files[relative], hashlib.sha256(content).hexdigest())

    def test_gate_identity_excludes_bytecode_cache_directories(self) -> None:
        before = trust._gate_identity(self.gate)
        identity = self.gate_identity_with_files((
            "quality_gate/__pycache__/cached.pyc",
            "quality_gate/elisp/__pycache__/nested/cached.py",
            "quality_gate/elisp/__pycache__/helper.sh",
        ), b"interpreter cache\n")
        for snapshot in ("identity_before", "identity_after"):
            with self.subTest(snapshot=snapshot):
                self.assertEqual(identity[snapshot]["gate"], before)

    def test_gate_elisp_helper_changed_during_check_is_an_identity_error(self) -> None:
        helper = self.gate / "quality_gate/elisp/qg-elisp-child.el"
        writer = ("import pathlib; "
                  f"p = pathlib.Path({str(helper)!r}); "
                  "p.write_text(p.read_text() + '\\n;; changed\\n'); print(1)")
        self.write_config(BASE_CONFIG.replace(
            'run = ["python3", "-c", "print(1)"]',
            f'run = [{json.dumps(sys.executable)}, "-c", {json.dumps(writer)}]',
        ))
        revision = self.directory_revision()
        self.fixture_runner = lambda: self.gate / "qg.py"
        result = self.run_qg_process(
            "check", "--json", "--policy-from", revision
        )
        document = self.parse_json(result)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertIn("gate file quality_gate/elisp/qg-elisp-child.el", document["error"])
        before = document["trust"]["identity_before"]["gate"]["files"]
        after = document["trust"]["identity_after"]["gate"]["files"]
        self.assertNotEqual(before["quality_gate/elisp/qg-elisp-child.el"],
                            after["quality_gate/elisp/qg-elisp-child.el"])

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
        revision = self.directory_revision()
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
        revision = self.directory_revision()
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
        revision = self.directory_revision()
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
        revision = self.directory_revision()
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

    def test_gate_inside_candidate_is_refused(self) -> None:
        revision = self.directory_revision()
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
        revision = self.directory_revision()
        result, document = self.trust_json(revision)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["schema"], 3)
        trust = document["trust"]
        self.assertEqual(trust["path"], revision)
        self.assertNotIn("policy_from", trust)
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
        revision = self.directory_revision()
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
        revision = self.directory_revision()
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
        revision = self.directory_revision()
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
