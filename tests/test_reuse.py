"""Tests for result reuse by recorded reads."""
from __future__ import annotations

import hashlib
import io
import datetime
import json
import os
import shutil
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from support import BASE_CONFIG, PYTHON_TEST_HEADER, FixtureCase, output

from quality_gate import reuse, tracing
from quality_gate.policy import UsageError

STRACE_DEB = (
    Path(os.environ["QG_STRACE_DEB"]) if "QG_STRACE_DEB" in os.environ else None
)
STRACE_PAYLOAD = (
    "69f88291a4e47f258b8e32b089c919a247509f063ef3d6afe5389939051102b3"
)


def with_run(run: list[str]) -> str:
    return BASE_CONFIG.replace(
        'run = ["python3", "-c", "print(1)"]',
        f"run = {json.dumps(run)}",
    )


class ReuseCase(FixtureCase):
    def require_deb(self) -> Path:
        if STRACE_DEB is not None and STRACE_DEB.is_file():
            return STRACE_DEB
        from quality_gate.tools import tool_binary

        binary = tool_binary("strace").read_bytes()
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:xz") as archive:
            member = tarfile.TarInfo("usr/bin/strace")
            member.mode = 0o755
            member.size = len(binary)
            archive.addfile(member, io.BytesIO(binary))
        package = self.base / "local-strace.deb"
        contents = bytearray(b"!<arch>\n")
        for name, payload in (("debian-binary", b"2.0\n"), ("data.tar.xz", data.getvalue())):
            header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(payload):<10}`\n"
            contents.extend(header.encode("ascii") + payload)
            if len(payload) % 2:
                contents.extend(b"\n")
        package.write_bytes(contents)
        return package

    def write_strace_lock(
        self,
        *,
        url: str | None = None,
        sha256: str | None = None,
        payload: str = STRACE_PAYLOAD,
    ) -> Path:
        lock = self.base / "strace-lock.toml"
        deb = self.require_deb()
        digest = sha256 or hashlib.sha256(deb.read_bytes()).hexdigest()
        lock.write_text(
            "[strace]\n"
            'version = "6.13+ds-1"\n'
            f"url = {json.dumps(url or deb.as_uri())}\n"
            f'sha256 = "{digest}"\n'
            f'payload_sha256 = "{payload}"\n'
            'format = "deb"\n'
            'binary = "usr/bin/strace"\n',
            encoding="utf-8",
        )
        return lock

    def install_strace(self) -> dict[str, str]:
        tools = self.base / "tools"
        lock = self.write_strace_lock()
        result = self.run_qg(
            "tools",
            "fetch",
            "--lock",
            str(lock),
            env={"QG_TOOLS_DIR": str(tools)},
        )
        self.assertEqual(result.returncode, 0, output(result))
        return {"QG_TOOLS_DIR": str(tools)}

    def run_reuse(
        self,
        label: str,
        *,
        env: dict[str, str] | None = None,
        extra: tuple[str, ...] = (),
    ) -> tuple[object, dict, list[dict]]:
        store = self.base / "store"
        store.mkdir(exist_ok=True)
        records = self.base / f"{label}.jsonl"
        fd = os.open(records, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            result = self.run_qg(
                "check",
                "--json",
                "--reuse-store",
                str(store),
                "--record-fd",
                str(fd),
                *extra,
                env=env,
                pass_fds=(fd,),
            )
        finally:
            os.close(fd)
        document = self.parse_json(result)
        merged = self.merge(records)
        self.assertEqual(merged.returncode, 0, output(merged))
        return result, document, self.record_objects(records)

    def merge(self, records: Path):
        return self.run_qg(
            "reuse",
            "merge",
            "--store",
            str(self.base / "store"),
            str(records),
            include_repo=False,
        )

    def record_objects(self, records: Path) -> list[dict]:
        return [
            json.loads(line)
            for line in records.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def store_records(self) -> list[Path]:
        store = self.base / "store"
        if not store.is_dir():
            return []
        return sorted(store.glob("*/record.json"))

    def check_outcome(self, document: dict) -> str:
        return str(self.check_by_id(document, "smoke")["outcome"])

    def first_pass(
        self, env: dict[str, str], run: list[str] | None = None
    ) -> tuple[object, list[dict]]:
        if run is not None:
            self.write_config(with_run(run))
        first, _document, records = self.run_reuse("first", env=env)
        self.assertEqual(first.returncode, 0, output(first))
        self.assertEqual(len(records), 1)
        return first, records

    def rerun_after(self, run: list[str], change) -> tuple[object, object]:
        env = self.install_strace()
        first, _records = self.first_pass(env, run)
        change()
        second, _document, _records = self.run_reuse("second", env=env)
        self.assertEqual(second.returncode, 0, output(second))
        self.assertNotIn("reused record", second.stderr)
        return first, second

    def assert_failing_rerun(
        self, label: str, env: dict[str, str], *, extra: tuple[str, ...] = ()
    ) -> None:
        result, document, records = self.run_reuse(label, env=env, extra=extra)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(self.check_outcome(document), "fail")
        self.assertNotIn("reused record", result.stderr)
        self.assertEqual(records, [])

    def merge_bad(self, records: list[dict], needle: str) -> None:
        bad = self.base / "bad.jsonl"
        bad.write_text(json.dumps(records[0]) + "\n", encoding="utf-8")
        merged = self.merge(bad)
        self.assertEqual(merged.returncode, 2, output(merged))
        self.assertIn(needle, merged.stderr)


class ReuseUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="qg-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "listing").mkdir()
        (self.root / "listing" / "one.py").write_text("VALUE = 1\n", encoding="utf-8")
        (self.root / "read.py").write_text("VALUE = 1\n", encoding="utf-8")

    def test_padded_process_ids_preserve_an_unfinished_child_stat(self) -> None:
        listing = self.root / "listing"
        target = listing / "one.py"
        trace = (
            f'42   openat(AT_FDCWD, "listing", O_RDONLY) = 3<{listing}>\n'
            '42   clone(child_stack=NULL, flags=SIGCHLD) = 43\n'
            '43   newfstatat(3, "one.py",  <unfinished ...>\n'
            '42   close(3) = 0\n'
            '43   <... newfstatat resumed>{st_mode=S_IFREG|0644}, 0) = 0\n'
        )
        recorder = tracing.Recorder(self.root, self.root / "trace")
        tracing._parse_trace_text(recorder, self.root, trace)
        self.assertTrue(recorder.reliable)
        self.assertEqual(recorder.inputs[str(target)], reuse.current_input(str(target))[1])

    def test_deleted_descriptor_annotations_do_not_hide_literal_paths(self) -> None:
        literal = self.root / "literal (deleted)"
        literal.write_text("content", encoding="utf-8")
        trace = (
            f'42   openat(AT_FDCWD, "{literal}", O_RDONLY) = 3<{literal}>\n'
            f'42   fstat(3<{literal}>, {{st_mode=S_IFREG|0644}}) = 0\n'
            f'42   close(3<{literal}>) = 0\n'
        )
        recorder = tracing.Recorder(self.root, self.root / "trace")
        tracing._parse_trace_text(recorder, self.root, trace)
        self.assertTrue(recorder.reliable)
        self.assertEqual(recorder.inputs[str(literal)], reuse.current_input(str(literal))[1])
        directory = self.root / "directory (deleted)"
        directory.mkdir()
        child = directory / "read.py"
        child.write_text("content", encoding="utf-8")
        recorder = tracing.Recorder(directory, self.root / "trace")
        tracing._parse_trace_text(
            recorder, directory,
            f'42   newfstatat(AT_FDCWD<{directory}>, "read.py", {{st_mode=S_IFREG|0644}}, 0) = 0\n',
        )
        self.assertTrue(recorder.reliable)
        self.assertIn(str(child), recorder.inputs)

    def test_a_deleted_descriptor_or_working_directory_is_unanalysable(self) -> None:
        target = self.root / "read.py"
        traces = (
            f'42   openat(AT_FDCWD, "{target}", O_RDONLY) = 3<{target}>\n'
            f'42   fstat(3<{target} (deleted)>, {{st_mode=S_IFREG|0644}}) = 0\n',
            f'42   newfstatat(AT_FDCWD<{self.root} (deleted)>, "read.py", '
            '{st_mode=S_IFREG|0644}, 0) = 0\n',
        )
        for trace in traces:
            with self.subTest(trace=trace):
                recorder = tracing.Recorder(self.root, self.root / "trace")
                tracing._parse_trace_text(recorder, self.root, trace)
                self.assertFalse(recorder.reliable)

    def test_unresolved_file_descriptors_make_the_trace_unanalysable(self) -> None:
        for line in (
            '42   newfstatat(9, "one.py", {st_mode=S_IFREG|0644}, 0) = 0',
            '42   openat(9, "missing.py", O_RDONLY) = -1 ENOENT (No such file)',
            '42   getdents64(9, [], 32768) = 0',
            '42   fstat(9, {st_mode=S_IFREG|0644}) = 0',
            '42   newfstatat(9, "", {st_mode=S_IFREG|0644}, AT_EMPTY_PATH) = 0',
            '42   readlinkat(9, "link", "target", 1024) = 6',
            '42   newfstatat(9, "one.py",  <unfinished ...>',
        ):
            with self.subTest(line=line):
                recorder = tracing.Recorder(self.root, self.root / "trace")
                tracing._parse_trace_text(recorder, self.root, line + "\n")
                self.assertFalse(recorder.reliable)

    def test_unresolved_non_file_stat_and_failed_open_do_not_hide_inputs(self) -> None:
        trace = (
            '42   newfstatat(9, "", {st_mode=S_IFIFO|0600}, AT_EMPTY_PATH) = 0\n'
            '42   openat(9, "file", O_RDONLY) = -1 EACCES (Permission denied)\n'
        )
        recorder = tracing.Recorder(self.root, self.root / "trace")
        tracing._parse_trace_text(recorder, self.root, trace)
        self.assertTrue(recorder.reliable)

    def test_descriptor_bases_use_annotations_working_directory_and_inherited_fds(self) -> None:
        fds = {(43, 3): str(self.root / "listing")}
        self.assertEqual(tracing._descriptor_base(self.root, fds, 43, "3</annotated>"), "/annotated")
        self.assertEqual(tracing._descriptor_base(self.root, fds, 43, "AT_FDCWD"), str(self.root))
        self.assertEqual(tracing._descriptor_base(self.root, fds, 43, "3"), str(self.root / "listing"))
        self.assertIsNone(tracing._descriptor_base(self.root, fds, 43, "4"))
        self.assertIsNone(tracing._descriptor_base(self.root, fds, 43, "unknown"))

    def test_audit_records_open_modes_paths_and_listings(self) -> None:
        read = str(self.root / "read.py")
        listing = str(self.root / "listing")
        created = str(self.root / "created.py")
        with tracing.collecting(self.root, self.root / "trace", ()) as recorder:
            tracing._audit("open", (read, "r", None))
            tracing._audit("open", (created, "w", None))
            tracing._audit("open", (read, None, os.O_RDONLY))
            tracing._audit(
                "open", (created, None, os.O_WRONLY | os.O_CREAT)
            )
            tracing._audit("open", (read, None, os.O_RDWR))
            tracing._audit("os.listdir", (listing,))
            tracing._audit("os.scandir", (listing,))
            self.assertIsNone(tracing._audit_path(1))
            self.assertIsNone(tracing._audit_path(object()))
        inputs = recorder.snapshot()
        self.assertIn(read, inputs)
        self.assertNotIn(created, inputs)
        self.assertIn(listing, inputs)

    def test_python_test_environment_drops_volatile_coverage_values(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"COVERAGE_ONE": "1", "COVERAGE_CORE": "ctrace"},
            clear=False,
        ):
            with mock.patch("quality_gate.python_tests.coverage_prefix_values",
                            return_value=["python3", "-I", "runner"]):
                environment = reuse.check_environment(
                    SimpleNamespace(adapter="python_tests"), self.root, self.root / "data"
                )
        self.assertNotIn("COVERAGE_ONE", environment)
        self.assertEqual(environment["COVERAGE_CORE"], "ctrace")
        self.assertEqual(json.loads(environment["QG_PYTHON"]), ["python3", "-I", "runner"])
        self.assertEqual(environment["PYTHONDONTWRITEBYTECODE"], "1")

    def test_input_matching_and_count_validation(self) -> None:
        read = self.root / "read.py"
        digest = reuse.current_input(str(read))[1]
        self.assertTrue(
            reuse._inputs_match({str(read): digest, str(self.root / "no.py"): None})
        )
        self.assertFalse(reuse._inputs_match({str(read): "0" * 64}))
        self.assertFalse(reuse._inputs_match({str(read): 1}))
        self.assertFalse(reuse._inputs_match([]))
        self.assertEqual(
            reuse._validate_count("tests_ran", 3, Path("x"), 1), 3
        )
        self.assertIsNone(
            reuse._validate_count("tests_ran", None, Path("x"), 1)
        )
        with self.assertRaises(UsageError):
            reuse._validate_count("tests_ran", True, Path("x"), 1)
        with self.assertRaises(UsageError):
            reuse._validate_count("tests_ran", -1, Path("x"), 1)

    def test_dangling_coverage_directory_never_reuses_a_result(self) -> None:
        from quality_gate.checks import _reuse_lookup

        link = self.root / "coverage"
        link.symlink_to(self.root / "missing")
        lookup = mock.Mock()
        session = SimpleNamespace(prune_ids=(), lookup=lookup)
        check = SimpleNamespace(id="tests")
        self.assertIsNone(_reuse_lookup(session, check, {"identity": "x"}, link))
        lookup.assert_not_called()

    def test_every_requested_prune_bypasses_the_reuse_store(self) -> None:
        from quality_gate.checks import _reuse_lookup

        cached = SimpleNamespace(record={})
        session = SimpleNamespace(prune_ids=("first", "second"), lookup=mock.Mock(return_value=cached))
        for identifier in ("first", "second"):
            check = SimpleNamespace(id=identifier, adapter="verification")
            self.assertIsNone(_reuse_lookup(session, check, {"identity": "x"}, None))
        session.lookup.assert_not_called()
        other = SimpleNamespace(id="other", adapter="verification")
        self.assertIs(_reuse_lookup(session, other, {"identity": "x"}, None), cached)

    def test_record_json_preserves_non_utf8_filesystem_paths(self) -> None:
        path = os.fsdecode(b"/tmp/non-utf8-\xff")
        self.assertEqual(json.loads(reuse._canonical({path: None})), {path: None})

    def test_a_missing_store_has_no_records(self) -> None:
        session = reuse.ReuseSession(self.root / "missing", self.root)
        try:
            self.assertIsNone(session.lookup({"check": "x"}))
        finally:
            session.close()

    def test_expiry_context_handles_checks_without_a_readable_baseline(self) -> None:
        from quality_gate import checks
        from quality_gate.policy import GateError

        self.assertEqual(checks._reuse_expired_entries(SimpleNamespace(baseline=None)), [])
        with mock.patch("quality_gate.checks._baseline_entries", side_effect=GateError("bad")):
            self.assertIsNone(checks._reuse_expired_entries(SimpleNamespace(baseline=self.root)))


class ReuseTests(ReuseCase):
    def test_a_check_is_reused_when_nothing_it_read_changed(self) -> None:
        self.write_config(
            with_run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "open('a.py').read(); print(1)",
                ]
            )
        )
        env = self.install_strace()
        first, records = self.first_pass(env)
        self.assertIn("passed", first.stderr)
        second, document, records = self.run_reuse("second", env=env)
        self.assertEqual(second.returncode, 0, output(second))
        self.assertIn("reused record at", second.stderr)
        self.assertEqual(self.check_outcome(document), "pass")
        self.assertTrue(self.check_by_id(document, "smoke")["reused_from"])
        self.assertEqual(records, [])

    def test_a_changed_read_file_reruns_the_check(self) -> None:
        self.rerun_after(
            [sys.executable, "-I", "-c", "open('a.py').read(); print(1)"],
            lambda: self.add_file("a.py", "print('changed')\n"),
        )

    def test_filenames_containing_a_deleted_marker_are_recorded(self) -> None:
        inside = self.add_file("real (deleted).py", "one")
        outside = self.base / "real (deleted)"
        outside.write_text("one", encoding="utf-8")
        env = self.install_strace()
        _first, records = self.first_pass(env, [
            sys.executable, "-I", "-c",
            f"open({str(inside)!r}).read(); open({str(outside)!r}).read(); print(1)",
        ])
        self.assertIn(str(inside), records[0]["inputs"])
        self.assertIn(str(outside), records[0]["inputs"])
        inside.write_text("two", encoding="utf-8")
        second, _document, _records = self.run_reuse("inside-changed", env=env)
        self.assertEqual(second.returncode, 0, output(second))
        self.assertNotIn("reused record", second.stderr)
        outside.write_text("two", encoding="utf-8")
        third, _document, _records = self.run_reuse("outside-changed", env=env)
        self.assertEqual(third.returncode, 0, output(third))
        self.assertNotIn("reused record", third.stderr)

    def test_directory_open_of_a_regular_file_remains_reusable(self) -> None:
        source = (
            "import os\n"
            "try: os.open('a.py', os.O_RDONLY | os.O_DIRECTORY)\n"
            "except NotADirectoryError: pass\n"
            "open('a.py').read(); print(1)\n"
        )
        env = self.install_strace()
        self.first_pass(env, [sys.executable, "-I", "-c", source])
        second, document, _records = self.run_reuse("directory-open", env=env)
        self.assertEqual(second.returncode, 0, output(second))
        self.assertIn("reused_from", self.check_by_id(document, "smoke"))
        self.add_file("a.py", "print('changed')\n")
        third, document, _records = self.run_reuse("directory-open-changed", env=env)
        self.assertEqual(third.returncode, 0, output(third))
        self.assertNotIn("reused_from", self.check_by_id(document, "smoke"))

    def test_missing_statfs_path_is_recorded_and_appearance_invalidates_reuse(self) -> None:
        target = self.repo / "new-mount"
        source = ("import ctypes; libc = ctypes.CDLL(None); buf = ctypes.create_string_buffer(1024); "
                  f"libc.statfs({os.fsencode(target)!r}, buf); print(1)")
        env = self.install_strace()
        self.first_pass(env, [sys.executable, "-I", "-c", source])
        second, document, _records = self.run_reuse("statfs-missing", env=env)
        self.assertEqual(second.returncode, 0, output(second))
        self.assertIn("reused_from", self.check_by_id(document, "smoke"))
        target.mkdir()
        third, document, _records = self.run_reuse("statfs-created", env=env)
        self.assertEqual(third.returncode, 0, output(third))
        self.assertNotIn("reused_from", self.check_by_id(document, "smoke"))

    def test_successful_statfs_prevents_reuse(self) -> None:
        source = ("import ctypes; libc = ctypes.CDLL(None); buf = ctypes.create_string_buffer(1024); "
                  "assert libc.statfs(b'.', buf) == 0; print(1)")
        env = self.install_strace()
        self.write_config(with_run([sys.executable, "-I", "-c", source]))
        result, document, records = self.run_reuse("statfs-success", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.check_outcome(document), "pass")
        self.assertEqual(records, [])

    def test_an_absent_file_that_appears_reruns_the_check(self) -> None:
        self.rerun_after(
            [
                sys.executable,
                "-I",
                "-c",
                "import os\ntry: os.stat('later.py')\n"
                "except OSError: pass\nprint(1)",
            ],
            lambda: self.add_file("later.py", "print('later')\n"),
        )

    def test_a_missing_access_lookup_that_appears_reruns(self) -> None:
        self.rerun_after(
            [sys.executable, "-I", "-c",
             "import os; os.access('later.py', os.F_OK); print(1)"],
            lambda: self.add_file("later.py", "VALUE = 1\n"),
        )

    def test_a_write_only_output_does_not_prevent_recording(self) -> None:
        output_file = self.base / "output.log"
        output_file.write_text("old", encoding="utf-8")
        env = self.install_strace()
        result, records = self.first_pass(
            env, [sys.executable, "-I", "-c",
                  f"import os; fd=os.open({str(output_file)!r}, os.O_WRONLY|os.O_TRUNC); "
                  "os.write(fd, b'new'); os.close(fd); print(1)"]
        )
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(len(records), 1)
        self.assertNotIn(str(output_file), records[0]["inputs"])

    def test_a_read_from_a_file_opened_for_writing_is_not_recorded(self) -> None:
        self.add_file("flag.py", "0\n")
        self.write_config(with_run([
            sys.executable, "-I", "-c",
            "import sys; f=open('flag.py','a+'); f.seek(0); "
            "print(1); sys.exit(int(f.read()))",
        ]))
        env = self.install_strace()
        first, _document, records = self.run_reuse("read-write", env=env)
        self.assertEqual(first.returncode, 0, output(first))
        self.assertEqual(records, [])
        self.add_file("flag.py", "1\n")
        second, _document, records = self.run_reuse("changed-flag", env=env)
        self.assertEqual(second.returncode, 1, output(second))
        self.assertNotIn("reused record", second.stderr)
        self.assertEqual(records, [])

    def test_file_content_cannot_be_confused_with_a_directory_marker(self) -> None:
        target = self.add_file("token.py", "qg: directory exists")
        self.write_config(with_run([
            sys.executable, "-I", "-c",
            "import pathlib,sys; p=pathlib.Path('token.py'); print(1); "
            "sys.exit(0 if p.is_file() and p.read_text() == 'qg: directory exists' else 1)",
        ]))
        env = self.install_strace()
        first, _document, records = self.run_reuse("file-marker", env=env)
        self.assertEqual(first.returncode, 0, output(first))
        self.assertEqual(len(records), 1)
        target.unlink()
        target.mkdir()
        self.assert_failing_rerun("directory-marker", env)

    def test_lstat_detects_when_a_file_becomes_a_symlink(self) -> None:
        self.add_file("a.py", "same")
        target = self.add_file("marker.py", "same")
        self.write_config(with_run([
            sys.executable, "-I", "-c",
            "import os,stat,sys; print(1); "
            "sys.exit(int(stat.S_ISLNK(os.lstat('marker.py').st_mode)))",
        ]))
        env = self.install_strace()
        first, _document, records = self.run_reuse("lstat-first", env=env)
        self.assertEqual(first.returncode, 0, output(first))
        self.assertEqual(len(records), 1)
        target.unlink()
        target.symlink_to("a.py")
        self.assert_failing_rerun("lstat-second", env)

    def test_fstat_detects_when_an_open_symlink_becomes_a_file(self) -> None:
        self.add_file("a.py", "same")
        target = self.repo / "marker.py"
        target.symlink_to("a.py")
        self.write_config(with_run([
            sys.executable, "-I", "-c",
            "import os,stat,sys; fd=os.open('marker.py',os.O_PATH|os.O_NOFOLLOW); "
            "mode=os.fstat(fd).st_mode; print(1); sys.exit(int(not stat.S_ISLNK(mode)))",
        ]))
        env = self.install_strace()
        first, _document, records = self.run_reuse("fstat-first", env=env)
        self.assertEqual(first.returncode, 0, output(first))
        self.assertEqual(len(records), 1)
        target.unlink()
        target.write_text("same", encoding="utf-8")
        self.assert_failing_rerun("fstat-second", env)

    def test_failed_readlink_is_invalidated_when_the_file_becomes_a_symlink(self) -> None:
        self.add_file("a.py", "same")
        target = self.add_file("marker.py", "same")
        self.write_config(with_run([
            sys.executable, "-I", "-c",
            "import os,sys\ntry: os.readlink('marker.py')\n"
            "except OSError: print(1); sys.exit(0)\nsys.exit(1)",
        ]))
        env = self.install_strace()
        first, _document, records = self.run_reuse("readlink-first", env=env)
        self.assertEqual(first.returncode, 0, output(first))
        self.assertEqual(len(records), 1)
        target.unlink()
        target.symlink_to("a.py")
        self.assert_failing_rerun("readlink-second", env)

    def test_a_missing_non_ascii_path_that_appears_reruns(self) -> None:
        self.rerun_after(
            [sys.executable, "-I", "-c",
             "import os; os.access('不存在-é.py', os.F_OK); print(1)"],
            lambda: self.add_file("不存在-é.py", "VALUE = 1\n"),
        )

    def test_a_changed_symlink_target_reruns_the_check(self) -> None:
        self.add_file("one.py", "VALUE = 1\n")
        self.add_file("two.py", "VALUE = 1\n")
        link = self.repo / "link.py"
        link.symlink_to("one.py")
        env = self.install_strace()
        self.first_pass(env, [sys.executable, "-I", "-c",
                              "import os; os.readlink('link.py'); print(1)"])
        link.unlink()
        link.symlink_to("two.py")
        result, _document, _records = self.run_reuse("changed-link", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertNotIn("reused record", result.stderr)

    def test_a_symlink_before_a_parent_component_resolves_as_the_kernel(self) -> None:
        self.add_file("input.py", "0\n")
        target = self.base / "external" / "input.py"
        target.parent.mkdir(parents=True)
        target.write_text("0\n", encoding="utf-8")
        (self.base / "external" / "deep").mkdir()
        (self.base / "external" / "deep2").mkdir()
        link = self.repo / "jump.py"
        link.symlink_to("../external/deep")
        source = (
            "import os, sys\n"
            "size = os.stat('jump.py/../input.py').st_size\n"
            "print(1)\n"
            "sys.exit(0 if size == 2 else 1)\n"
        )
        env = self.install_strace()
        _first, records = self.first_pass(env, [sys.executable, "-I", "-c", source])
        self.assertIn(str(target), records[0]["inputs"])
        self.assertIn(str(link), records[0]["symlinks"])
        target.write_text("changed\n", encoding="utf-8")
        self.assert_failing_rerun("symlink-target", env)
        target.write_text("0\n", encoding="utf-8")
        link.unlink()
        link.symlink_to("../external/deep2")
        result, _document, _records = self.run_reuse("symlink-link", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertNotIn("reused record", result.stderr)

    def test_a_changed_permission_bit_reruns_the_check(self) -> None:
        target = self.add_file("tool.py", "VALUE = 1\n")
        target.chmod(0o755)
        source = (
            "import os, sys\n"
            "print(1)\n"
            "sys.exit(0 if os.access('tool.py', os.X_OK) else 1)\n"
        )
        env = self.install_strace()
        _first, records = self.first_pass(env, [sys.executable, "-I", "-c", source])
        metadata = records[0]["metadata"][str(target)]
        self.assertEqual(metadata["type"], "file")
        self.assertEqual(metadata["mode"], 0o755)
        target.chmod(0o644)
        self.assert_failing_rerun("permission", env)

    def test_a_write_through_a_hardlink_invalidates_the_record(self) -> None:
        flag = self.add_file("flag.py", "0")
        os.link(flag, self.repo / "alias.py")
        self.write_config(with_run([
            sys.executable, "-I", "-c",
            "import os,sys; value=open('flag.py').read(); "
            "fd=os.open('alias.py', os.O_WRONLY|os.O_TRUNC); "
            "os.write(fd,b'1'); os.close(fd); print(1); sys.exit(int(value))",
        ]))
        env = self.install_strace()
        first, _document, records = self.run_reuse("hardlink-first", env=env)
        self.assertEqual(first.returncode, 0, output(first))
        self.assertEqual(records, [])
        second, _document, records = self.run_reuse("hardlink-second", env=env)
        self.assertEqual(second.returncode, 1, output(second))
        self.assertNotIn("reused record", second.stderr)
        self.assertEqual(records, [])

    def test_an_unread_file_does_not_invalidate_a_command_without_file_arguments(self) -> None:
        env = self.install_strace()
        self.first_pass(env, [sys.executable, "-I", "-c", "open('a.py').read(); print(1)"])
        self.add_file("unrelated.py", "VALUE = 1\n")
        result, _document, _records = self.run_reuse("unrelated", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("reused record", result.stderr)

    def test_a_listed_directory_that_gains_an_entry_reruns_the_check(self) -> None:
        self.write_config(
            with_run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import os\nos.listdir('listing'); print(1)",
                ]
            )
        )
        (self.repo / "listing").mkdir()
        self.add_file("listing/one.py", "print('one')\n")
        env = self.install_strace()
        first, _document, _records = self.run_reuse("first", env=env)
        self.assertEqual(first.returncode, 0, output(first))
        self.add_file("listing/two.py", "print('two')\n")
        second, _document, _records = self.run_reuse("second", env=env)
        self.assertEqual(second.returncode, 0, output(second))
        self.assertNotIn("reused record", second.stderr)

    def test_a_read_after_chdir_is_tracked(self) -> None:
        (self.repo / "nested").mkdir()
        self.add_file("nested/read.py", "VALUE = 1\n")
        self.rerun_after(
            [sys.executable, "-I", "-c",
             "import os; os.chdir('nested'); open('read.py').read(); print(1)"],
            lambda: self.add_file("nested/read.py", "VALUE = 2\n"),
        )

    def test_a_child_inherits_directory_descriptors(self) -> None:
        (self.repo / "nested").mkdir()
        self.add_file("nested/read.py", "VALUE = 1\n")
        self.rerun_after(
            [sys.executable, "-I", "-c",
             "import os; d=os.open('nested', os.O_RDONLY); p=os.fork(); "
             "(os.stat('read.py', dir_fd=d), os._exit(0)) if not p "
             "else (os.waitpid(p, 0), print(1))"],
            lambda: self.add_file("nested/read.py", "VALUE = 2\n"),
        )

    def test_changed_command_verdict_settings_are_not_reused(self) -> None:
        env = self.install_strace()
        self.first_pass(env, [sys.executable, "-I", "-c", "print(1)"])
        config = with_run([sys.executable, "-I", "-c", "print(1)"])
        config = config.replace('adapter = "command"',
                                'adapter = "command"\nmust_match = "NEVER"')
        self.write_config(config)
        result, document, records = self.run_reuse("settings", env=env)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertNotIn("reused record", result.stderr)
        self.assertNotEqual(self.check_outcome(document), "pass")
        self.assertEqual(records, [])

    def test_external_input_with_temporary_prefix_is_not_excluded(self) -> None:
        external = self.base / "qg-coverage-external"
        external.mkdir()
        data = external / "data.txt"
        data.write_text("one", encoding="utf-8")
        env = self.install_strace()
        env["TMPDIR"] = str(self.base)
        self.first_pass(env, [sys.executable, "-I", "-c",
                              f"open({str(data)!r}).read(); print(1)"])
        data.write_text("two", encoding="utf-8")
        result, _document, _records = self.run_reuse("external", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertNotIn("reused record", result.stderr)

    def test_a_changed_command_reruns_the_check(self) -> None:
        env = self.install_strace()
        self.first_pass(env, [sys.executable, "-I", "-c", "print(1)"])
        self.write_config(
            with_run([sys.executable, "-I", "-c", "print(2)"])
        )
        second, _document, _records = self.run_reuse("second", env=env)
        self.assertEqual(second.returncode, 0, output(second))
        self.assertNotIn("reused record", second.stderr)

    def test_a_changed_environment_value_reruns_the_check(self) -> None:
        self.write_config(
            with_run([sys.executable, "-I", "-c", "print(1)"])
        )
        first = {"QG_REUSE_VALUE": "one"}
        second = {"QG_REUSE_VALUE": "two"}
        one = self.install_strace()
        one.update(first)
        self.first_pass(one, [sys.executable, "-I", "-c", "print(1)"])
        two = self.install_strace()
        two.update(second)
        result, _document, _records = self.run_reuse("second", env=two)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertNotIn("reused record", result.stderr)

    def test_a_changed_gate_program_reruns_the_check(self) -> None:
        self.write_config(
            with_run([sys.executable, "-I", "-c", "print(1)"])
        )
        gate = self.fixture_gate()
        env = self.install_strace()
        first = self.direct_check(gate, "first", env)
        self.assertEqual(first.returncode, 0, output(first))
        module = gate / "quality_gate" / "reuse.py"
        module.write_text(
            module.read_text(encoding="utf-8") + "\n# changed gate\n",
            encoding="utf-8",
        )
        second = self.direct_check(gate, "second", env)
        self.assertEqual(second.returncode, 0, output(second))
        self.assertNotIn("reused record", second.stderr)

    def direct_check(
        self, gate: Path, label: str, env: dict[str, str]
    ) -> object:
        store = self.base / "store"
        store.mkdir(exist_ok=True)
        records = self.base / f"{label}.jsonl"
        fd = os.open(records, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            import subprocess

            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(gate / "qg.py"),
                    "--repo",
                    str(self.repo),
                    "check",
                    "--json",
                    "--reuse-store",
                    str(store),
                    "--record-fd",
                    str(fd),
                ],
                cwd=self.repo,
                env=self.env(env),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                pass_fds=(fd,),
            )
        finally:
            os.close(fd)
        merge = subprocess.run(
            [
                sys.executable,
                "-I",
                str(gate / "qg.py"),
                "reuse",
                "merge",
                "--store",
                str(store),
                str(records),
            ],
            cwd=self.repo,
            env=self.env(env),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        self.assertEqual(merge.returncode, 0, output(merge))
        return result

    def test_a_failed_check_leaves_no_record(self) -> None:
        self.write_config(
            with_run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import sys; print(1); sys.exit(3)",
                ]
            )
        )
        env = self.install_strace()
        result, document, records = self.run_reuse("failed", env=env)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(self.check_outcome(document), "fail")
        self.assertEqual(records, [])

    def test_a_failing_check_is_never_reused_from_a_stale_record(self) -> None:
        self.write_config(
            with_run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import sys\n"
                    "print(1)\n"
                    "sys.exit(int(open('flag.py').read().strip()))",
                ]
            )
        )
        self.add_file("flag.py", "0\n")
        env = self.install_strace()
        first, _document, records = self.run_reuse("passing", env=env)
        self.assertEqual(first.returncode, 0, output(first))
        self.assertEqual(len(records), 1)
        self.add_file("flag.py", "1\n")
        second, document, records = self.run_reuse("failing", env=env)
        self.assertEqual(second.returncode, 1, output(second))
        self.assertNotIn("reused record", second.stderr)
        self.assertEqual(self.check_outcome(document), "fail")
        self.assertEqual(records, [])

    def test_without_a_reuse_store_every_check_runs(self) -> None:
        marker = self.base / "runs.log"
        self.write_config(
            with_run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    f"open({str(marker)!r}, 'a').write('run\\n'); print(1)",
                ]
            )
        )
        self.assertEqual(self.run_qg("check").returncode, 0)
        self.assertEqual(self.run_qg("check").returncode, 0)
        self.assertEqual(len(marker.read_text(encoding="utf-8").splitlines()), 2)


class ReuseDeadlineTests(ReuseCase):
    def assert_stalled(self, target: str, step: str, env: dict[str, str] | None = None,
                       fd: int | None = None) -> None:
        from quality_gate import checks
        from quality_gate.policy import load_config

        self.write_config(with_run([sys.executable, "-I", "-c", "print(1)"]).replace(
            'adapter = "command"', 'adapter = "command"\nbudget_seconds = 1'))
        config = load_config(self.repo)
        started = time.monotonic()
        with mock.patch.dict(os.environ, env or {}), reuse.active(self.base / "store", self.repo, fd):
            with mock.patch(target, side_effect=lambda *args: time.sleep(3)):
                result = checks.run_check(self.repo, config, config.checks["smoke"],
                                          ["a.py"], {"a.py": "python"}, prefix="check: smoke")
        self.assertEqual(result.execution, "budget")
        self.assertEqual(result.outcome, "fail")
        self.assertIn(step, result.reason)
        self.assertLess(time.monotonic() - started, 2.5)

    def test_stalled_trace_analysis_respects_the_check_budget(self) -> None:
        env = self.install_strace()
        records = self.base / "timeout.jsonl"
        fd = os.open(records, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        self.assert_stalled("quality_gate.tracing._parse_trace_text", "trace analysis", env, fd)
        self.assertEqual(records.read_bytes(), b"")

    def test_stalled_reuse_lookup_respects_the_check_budget(self) -> None:
        self.assert_stalled("quality_gate.checks._reuse_context", "reuse context")


class ReuseAdapterTests(ReuseCase):
    def test_expired_minimum_baseline_cannot_reuse_a_passing_result(self) -> None:
        from quality_gate import checks, ratchet
        from quality_gate.policy import load_config
        from test_verification import verification_baseline, verification_config

        self.add_file("pkg/mod.py", "VALUE = 1\n")
        self.write_config(verification_config())
        self.add_file("quality-gate-verification.toml", verification_baseline([{
            "subject": "tests:tests:executed", "bound": 1,
            "reason": "measured", "expires": "2026-01-02",
        }]))
        env = self.install_strace()
        config = load_config(self.repo)
        check = config.checks["verification"]
        prior = {"tests": SimpleNamespace(
            outcome="pass", tests_ran=1, tests_skipped=0, test_results=None,
            measurement={"tests": 1}, evidence_path=None, adapter="python_tests",
        )}
        store, records = self.base / "store", self.base / "expiry.jsonl"
        store.mkdir()

        def check_on(today: datetime.date, fd: int | None = None):
            def evaluate_at(*args, **kwargs):
                return ratchet.evaluate(*args, **kwargs, today=today)

            with mock.patch.dict(os.environ, env), mock.patch(
                "quality_gate.checks.date"
            ) as clock, mock.patch("quality_gate.checks.evaluate", side_effect=evaluate_at):
                clock.today.return_value = today
                with reuse.active(store, self.repo, fd):
                    return checks.run_check(
                        self.repo, config, check, ["pkg/mod.py"], {"pkg/mod.py": "python"},
                        prefix="check: verification", prior=prior,
                    )

        fd = os.open(records, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        first = check_on(datetime.date(2026, 1, 1), fd)
        self.assertEqual(first.outcome, "pass")
        self.assertEqual(reuse.merge_records(store, records), 0)
        on_expiry = check_on(datetime.date(2026, 1, 2))
        self.assertIsNotNone(on_expiry.reused_from)
        expired = check_on(datetime.date(2026, 1, 3))
        self.assertIsNone(expired.reused_from)
        self.assertEqual(expired.outcome, "fail")

    def test_reused_python_tests_keep_evidence_for_later_checks(self) -> None:
        from quality_gate.coverage_tool import coverage_installation
        from test_python_crap import crap_config

        (self.repo / "a.py").unlink()
        self.add_file("pkg/__init__.py", "")
        self.add_file("pkg/example.py", "def add(a, b):\n    return a + b\n")
        self.add_file("tests/test_sample.py", (
            PYTHON_TEST_HEADER + "from pkg.example import add\n"
            "class Sample(unittest.TestCase):\n"
            "    def test_add(self): self.assertEqual(add(1, 2), 3)\n"
        ))
        self.write_config(crap_config())
        env = self.install_strace()
        source = coverage_installation()
        shutil.copytree(source, Path(env["QG_TOOLS_DIR"]) / source.name)
        first, first_document, records = self.run_reuse("python-first", env=env)
        self.assertEqual(first.returncode, 0, output(first))
        test_record = next(record for record in records if record["check"] == "tests")
        prefix = json.loads(test_record["environment"]["QG_PYTHON"])
        self.assertEqual(prefix[0], sys.executable)
        self.assertTrue(prefix[3].endswith("/data"))
        second, document, _records = self.run_reuse("python-second", env=env)
        self.assertEqual(second.returncode, 0, output(second))
        self.assertIn("check: tests: reused record", second.stderr)
        self.assertEqual(self.check_by_id(document, "tests")["test_results"],
                         self.check_by_id(first_document, "tests")["test_results"])
        self.assertEqual(self.check_by_id(document, "crap")["outcome"], "pass")
        self.write_config(crap_config(threshold=7))
        third, document, _records = self.run_reuse("python-third", env=env)
        self.assertEqual(third.returncode, 0, output(third))
        self.assertIn("check: tests: reused record", third.stderr)
        self.assertNotIn("check: crap: reused record", third.stderr)
        self.assertEqual(self.check_by_id(document, "crap")["outcome"], "pass")
        fourth, document, _records = self.run_reuse(
            "python-prune", env=env, extra=("--prune", "crap")
        )
        self.assertEqual(fourth.returncode, 0, output(fourth))
        self.assertNotIn("check: crap: reused record", fourth.stderr)
        self.assertTrue(document["prune"]["performed"])


class ReuseTrustTests(ReuseCase):
    def test_a_traced_process_cannot_write_the_record_trace_or_store(self) -> None:
        self.write_config(
            with_run([sys.executable, "-I", "-c", "print(1)"])
        )
        env = self.install_strace()
        first, _document, _records = self.run_reuse("first", env=env)
        self.assertEqual(first.returncode, 0, output(first))
        before = {
            path: path.read_bytes() for path in self.store_records()
        }
        results = self.base / "attack-results"
        store = self.base / "store"
        script = self.add_file(
            "attack.py",
            "import os, pathlib, sys\n"
            "record_fd, store = int(sys.argv[1]), sys.argv[2]\n"
            f"results = pathlib.Path({str(results)!r})\n"
            "results_fd = os.open(results, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o666)\n"
            "if os.geteuid() == 0:\n"
            "    os.setgroups([])\n"
            "    os.setgid(65534)\n"
            "    os.setuid(65534)\n"
            "found = []\n"
            "try:\n"
            "    os.write(record_fd, b'evil\\n')\n"
            "    found.append('record-fd')\n"
            "except OSError:\n"
            "    pass\n"
            "for pid in os.listdir('/proc'):\n"
            "    if not pid.isdigit():\n"
            "        continue\n"
            "    fds = f'/proc/{pid}/fd'\n"
            "    try:\n"
            "        names = os.listdir(fds)\n"
            "    except OSError:\n"
            "        continue\n"
            "    for name in names:\n"
            "        try:\n"
            "            target = os.readlink(f'{fds}/{name}')\n"
            "        except OSError:\n"
            "            continue\n"
            "        if not (target.startswith(store) or target.endswith('/trace')):\n"
            "            continue\n"
            "        try:\n"
            "            with open(f'{fds}/{name}', 'wb') as stream:\n"
            "                stream.write(b'evil')\n"
            "            found.append(target)\n"
            "        except OSError:\n"
            "            pass\n"
            "try:\n"
            "    (pathlib.Path(store) / 'direct').write_text('evil')\n"
            "    found.append('store-direct')\n"
            "except OSError:\n"
            "    pass\n"
            "os.write(results_fd, '\\n'.join(found).encode())\n"
            "os.close(results_fd)\n"
            "print(1)\n",
        )
        self.write_config(
            with_run(
                [sys.executable, "-I", str(script), "50", str(store)]
            )
        )
        fd = os.open(self.base / "attack.jsonl", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.dup2(fd, 50)
        os.close(fd)
        try:
            result = self.run_qg(
                "check",
                "--json",
                "--reuse-store",
                str(store),
                "--record-fd",
                "50",
                env={**env, "ATTACK_SCRIPT": str(script)},
                pass_fds=(50,),
            )
        finally:
            os.close(50)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(results.read_text(encoding="utf-8"), "")
        after = {path: path.read_bytes() for path in self.store_records() if path in before}
        self.assertEqual(before, after)

    def test_gate_and_tracer_descriptor_directories_are_inaccessible(self) -> None:
        results = self.base / "proc-results"
        script = self.add_file("proc_attack.py", (
            "import os, pathlib\n"
            "tracer = os.getppid()\n"
            "gate = int(pathlib.Path(f'/proc/{tracer}/stat').read_text().split()[3])\n"
            "succeeded = []\n"
            "for fd in list(range(3, 16)) + [50]:\n"
            "    try:\n"
            "        os.write(fd, b'evil')\n"
            "        succeeded.append(f'self:{fd}')\n"
            "    except OSError: pass\n"
            "for pid in (gate, tracer):\n"
            "    for fd in list(range(3, 16)) + [50]:\n"
            "        try:\n"
            "            descriptor = os.open(f'/proc/{pid}/fd/{fd}', os.O_WRONLY)\n"
            "            os.write(descriptor, b'evil')\n"
            "            os.close(descriptor)\n"
            "            succeeded.append(f'{pid}:{fd}')\n"
            "        except OSError: pass\n"
            f"pathlib.Path({str(results)!r}).write_text(','.join(succeeded))\n"
            "print(1)\n"
        ))
        self.write_config(with_run([sys.executable, "-I", str(script)]))
        env = self.install_strace()
        result, _document, records = self.run_reuse("proc-attack", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(results.read_text(), "")
        self.assertEqual(records, [])

    def test_merge_rejects_non_json_numbers(self) -> None:
        source = self.base / "bad-number.jsonl"
        source.write_text('{"schema": NaN}\n', encoding="utf-8")
        result = self.merge(source)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("invalid JSON constant", result.stderr)

    def test_merge_rejects_a_wrong_program_hash(self) -> None:
        env = self.install_strace()
        _first, records = self.first_pass(
            env, [sys.executable, "-I", "-c", "print(1)"]
        )
        records[0]["program"] = "0" * 64
        self.merge_bad(records, "program")

    def test_merge_rejects_a_malformed_entry(self) -> None:
        env = self.install_strace()
        _first, records = self.first_pass(
            env, [sys.executable, "-I", "-c", "print(1)"]
        )
        records[0]["inputs"] = ["not", "a", "table"]
        self.merge_bad(records, "inputs")


class DebToolTests(ReuseCase):
    def test_deb_extracts_and_verifies_the_pinned_strace(self) -> None:
        env = self.install_strace()
        binary = (
            Path(env["QG_TOOLS_DIR"])
            / "strace-6.13+ds-1"
            / "usr"
            / "bin"
            / "strace"
        )
        self.assertTrue(binary.is_file())
        self.assertTrue(binary.stat().st_mode & 0o111)
        version = self.run_qg("tools", "path", "strace", env=env)
        self.assertEqual(version.returncode, 0, output(version))
        self.assertEqual(version.stdout.strip(), str(binary))

    def refused_deb(self, needle: str, **fields: str) -> None:
        tools = self.base / "tools"
        lock = self.write_strace_lock(**fields)
        result = self.run_qg(
            "tools", "fetch", "--lock", str(lock), env={"QG_TOOLS_DIR": str(tools)}
        )
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn(needle, result.stderr)
        self.assertFalse((tools / "strace-6.13+ds-1").exists())

    def test_deb_rejects_an_invalid_ar_header(self) -> None:
        package = bytearray(self.require_deb().read_bytes())
        package[66] = 0
        bad = self.base / "invalid.deb"
        bad.write_bytes(package)
        self.refused_deb("invalid ar header", url=bad.as_uri(),
                         sha256=hashlib.sha256(package).hexdigest())

    def test_deb_checksum_mismatch_is_refused(self) -> None:
        self.refused_deb("sha256 mismatch", sha256="0" * 64)

    def test_deb_payload_mismatch_is_refused(self) -> None:
        self.refused_deb("payload sha256 mismatch", payload="0" * 64)


class RealTraceTests(ReuseCase):
    def test_a_real_trace_records_interpreter_file_absence_and_listing(self) -> None:
        self.write_config(
            with_run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import os, pathlib\n"
                    "pathlib.Path('read.py').read_text()\n"
                    "try: os.stat('absent.py')\n"
                    "except OSError: pass\n"
                    "os.listdir('listing')\n"
                    "print(1)",
                ]
            )
        )
        self.add_file("read.py", "VALUE = 1\n")
        (self.repo / "listing").mkdir()
        self.add_file("listing/one.py", "VALUE = 1\n")
        env = self.install_strace()
        result, _document, records = self.run_reuse("trace", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(len(records), 1)
        inputs = records[0]["inputs"]
        interpreter = str(sys.executable)
        self.assertIn(interpreter, inputs)
        self.assertIn(str(self.repo / "read.py"), inputs)
        self.assertIsNone(inputs[str(self.repo / "absent.py")])
        self.assertIn(str(self.repo / "listing"), inputs)
        expected = hashlib.sha256(b"one.py\0").hexdigest()
        self.assertEqual(inputs[str(self.repo / "listing")], expected)

    def test_changed_trusted_tool_pin_cannot_reuse_an_old_result(self) -> None:
        from quality_gate.payload import payload_digest

        env = self.install_strace()
        tools = Path(env["QG_TOOLS_DIR"])
        digests = {}
        for version, body in (("1", "echo 1\n"), ("2", "exit 1\n")):
            directory = tools / f"probe-{version}"
            directory.mkdir()
            binary = directory / "probe"
            binary.write_text("#!/bin/sh\n" + body, encoding="utf-8")
            binary.chmod(0o755)
            digests[version] = payload_digest(directory)
        strace_lock = self.write_strace_lock().read_text(encoding="utf-8")

        def write_lock(version: str) -> None:
            self.add_file("tools.lock.toml", strace_lock + (
                f'\n[probe]\nversion = "{version}"\nurl = "file:///unused"\n'
                f'sha256 = "{"0" * 64}"\npayload_sha256 = "{digests[version]}"\n'
                'binary = "probe"\n'
            ))

        self.write_config(with_run(["{tool:probe}"]))
        write_lock("1")
        self.commit_all("first tool")
        first, _document, records = self.run_reuse("tool-first", env=env, extra=("--policy-from", "HEAD"))
        self.assertEqual(first.returncode, 0, output(first))
        self.assertEqual(len(records), 1)
        write_lock("2")
        self.commit_all("changed tool")
        self.assert_failing_rerun("tool-second", env, extra=("--policy-from", "HEAD"))

    def test_a_missing_tracer_cannot_reuse_an_existing_record(self) -> None:
        self.write_config(with_run([sys.executable, "-I", "-c", "print(1)"]))
        env = self.install_strace()
        first, _document, _records = self.run_reuse("available", env=env)
        self.assertEqual(first.returncode, 0, output(first))
        binary = Path(env["QG_TOOLS_DIR"]) / "strace-6.13+ds-1/usr/bin/strace"
        binary.unlink()
        second, document, records = self.run_reuse("unavailable", env=env)
        self.assertEqual(second.returncode, 1, output(second))
        self.assertEqual(self.check_outcome(document), "unsupported")
        self.assertNotIn("reused record", second.stderr)
        self.assertIn("strace", second.stderr)
        self.assertEqual(records, [])

    def test_the_trace_records_kernel_loaded_script_and_elf_interpreters(self) -> None:
        script = self.add_file("launch.py", "#!/usr/bin/env python3\nprint(1)\n")
        script.chmod(0o755)
        self.write_config(with_run([str(script)]))
        env = self.install_strace()
        result, _document, records = self.run_reuse("interpreters", env=env)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(len(records), 1)
        inputs = records[0]["inputs"]
        self.assertIn("/usr/bin/env", inputs)
        self.assertIn("/lib64/ld-linux-x86-64.so.2", inputs)

    def test_a_changed_kernel_loaded_interpreter_reruns_the_check(self) -> None:
        interpreter = self.add_file("interpreter.py", "#!/bin/sh\necho 1\n")
        interpreter.chmod(0o755)
        script = self.add_file("entry.py", f"#!{interpreter}\nignored\n")
        script.chmod(0o755)
        self.write_config(with_run([str(script)]))
        env = self.install_strace()
        first, _document, records = self.run_reuse("interpreter-first", env=env)
        self.assertEqual(first.returncode, 0, output(first))
        self.assertIn(str(interpreter), records[0]["inputs"])
        interpreter.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        self.assert_failing_rerun("interpreter-second", env)

    def test_a_missing_tracer_fails_a_reuse_enabled_check(self) -> None:
        self.write_config(
            with_run([sys.executable, "-I", "-c", "print(1)"])
        )
        empty = self.base / "empty-tools"
        result, document, records = self.run_reuse(
            "missing", env={"QG_TOOLS_DIR": str(empty)}
        )
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(self.check_outcome(document), "unsupported")
        self.assertIn("strace", result.stderr)
        self.assertIn("tools.lock.toml", result.stderr)
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
