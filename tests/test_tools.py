"""Tests for pinned tool fetching and path resolution."""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from support import BASE_CONFIG, GATE, RUFF_VERSION, FixtureCase, output

from quality_gate.policy import UnsupportedError
from quality_gate.tools import (
    PayloadError,
    lock_override,
    payload_digest,
    verify_tool_directory,
)

VERSION = "9.9.9"


class ToolsTests(FixtureCase):
    def make_tarball(
        self,
        name: str = "tool.tar.gz",
        *,
        files: dict[str, bytes] | None = None,
        links: dict[str, str] | None = None,
        absolute: list[str] | None = None,
        directories: list[str] | None = None,
        executable: bool = True,
    ) -> Path:
        path = self.base / name
        contents = files
        if contents is None:
            contents = {
                "jscpd": b"#!/bin/sh\necho fake\n",
                "LICENSE": b"MIT\n",
            }
        with tarfile.open(path, "w:gz") as archive:
            for directory in directories or []:
                info = tarfile.TarInfo(directory)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
            for member, content in contents.items():
                info = tarfile.TarInfo(member)
                info.size = len(content)
                info.mode = (
                    0o755
                    if executable and member.endswith("jscpd")
                    else 0o644
                )
                archive.addfile(info, io.BytesIO(content))
            for member, target in (links or {}).items():
                info = tarfile.TarInfo(member)
                info.type = tarfile.SYMTYPE
                info.linkname = target
                archive.addfile(info)
            for member in absolute or []:
                info = tarfile.TarInfo(member)
                info.size = 4
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(b"evil"))
        return path

    def make_wheel(
        self,
        name: str = "tool.whl",
        *,
        files: dict[str, bytes] | None = None,
        links: dict[str, str] | None = None,
    ) -> Path:
        path = self.base / name
        contents = files
        if contents is None:
            contents = {
                "pkg/__init__.py": b"VALUE = 1\n",
                "pkg/mod.py": b"\n",
            }
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for member, content in contents.items():
                info = zipfile.ZipInfo(member)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, content)
            for member, target in (links or {}).items():
                info = zipfile.ZipInfo(member)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, target)
        return path

    def sha256(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def write_lock(
        self,
        url: str,
        digest: str,
        *,
        version: str = VERSION,
        binary: str = "jscpd",
        archive_format: str | None = None,
        path: Path | None = None,
        payload: str | None = None,
        include_payload: bool = True,
    ) -> Path:
        lock = path or (self.base / "lock.toml")
        lines = [
            "[jscpd]",
            f'version = "{version}"',
            f"url = {json.dumps(url)}",
            f'sha256 = "{digest}"',
        ]
        if include_payload:
            lines.append(
                f'payload_sha256 = "{payload or "0" * 64}"'
            )
        if archive_format is not None:
            lines.append(f'format = "{archive_format}"')
        lines.append(f'binary = "{binary}"')
        lock.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return lock

    def archive_payload(
        self,
        archive: Path,
        *,
        binary: str = "jscpd",
        archive_format: str = "tar",
    ) -> str:
        from quality_gate.tools import Tool, _extract_archive

        if str(GATE) not in sys.path:
            sys.path.insert(0, str(GATE))
        with tempfile.TemporaryDirectory(dir=self.base) as temporary:
            build = Path(temporary) / "build"
            build.mkdir()
            tool = Tool(
                name="jscpd",
                version=VERSION,
                url=archive.as_uri(),
                sha256="0" * 64,
                payload_sha256="0" * 64,
                binary=binary,
                format=archive_format,
            )
            _extract_archive(archive, build, tool)
            installed = build / binary
            if installed.is_file():
                mode = installed.stat().st_mode & 0o777
                if not mode & 0o111:
                    os.chmod(installed, mode | 0o111)
            return payload_digest(build)

    def fetch(
        self, lock: Path, tools: Path, *extra: str
    ) -> object:
        return self.run_qg(
            "tools",
            "fetch",
            "--lock",
            str(lock),
            *extra,
            env={"QG_TOOLS_DIR": str(tools)},
        )

    def fetch_refused(self, archive: Path, needle: str) -> Path:
        lock = self.write_lock(archive.as_uri(), self.sha256(archive))
        tools = self.base / "tools"
        result = self.fetch(lock, tools)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn(needle, text)
        return tools

    def assert_not_installed(self, tools: Path) -> None:
        self.assertFalse((tools / f"jscpd-{VERSION}").exists())

    def fetch_wheel_refused(self, wheel: Path, needle: str) -> None:
        lock = self.write_lock(
            wheel.as_uri(),
            self.sha256(wheel),
            binary="pkg/__init__.py",
            archive_format="wheel",
        )
        tools = self.base / "tools"
        result = self.fetch(lock, tools)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn(needle, text)
        self.assert_not_installed(tools)

    def fetch_ok(self, archive: Path) -> tuple[Path, object]:
        lock = self.write_lock(
            archive.as_uri(),
            self.sha256(archive),
            payload=self.archive_payload(archive),
        )
        tools = self.base / "tools"
        result = self.fetch(lock, tools)
        self.assertEqual(result.returncode, 0, output(result))
        return tools, result

    def test_fetch_with_correct_hash_installs(self) -> None:
        tools, result = self.fetch_ok(self.make_tarball())
        binary = tools / f"jscpd-{VERSION}" / "jscpd"
        self.assertTrue(binary.is_file(), output(result))
        self.assertTrue(binary.stat().st_mode & 0o111)
        self.assertEqual(binary.read_text(encoding="utf-8"), "#!/bin/sh\necho fake\n")
        self.assertTrue((tools / f"jscpd-{VERSION}" / "LICENSE").is_file())
        self.assertIn("installed jscpd", result.stdout)

    def test_fetch_makes_the_binary_executable(self) -> None:
        tools, _result = self.fetch_ok(self.make_tarball(executable=False))
        binary = tools / f"jscpd-{VERSION}" / "jscpd"
        self.assertTrue(binary.stat().st_mode & 0o111)

    def test_fetch_with_wrong_hash_installs_nothing(self) -> None:
        archive = self.make_tarball()
        lock = self.write_lock(archive.as_uri(), "0" * 64)
        tools = self.base / "tools"
        result = self.fetch(lock, tools)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("sha256 mismatch", text)
        self.assertIn("nothing installed", text)
        self.assert_not_installed(tools)
        self.assertEqual(list(tools.iterdir()), [])

    def test_fetch_refuses_path_traversal_member(self) -> None:
        archive = self.make_tarball(
            files={"../escape": b"evil\n", "jscpd": b"binary\n"}
        )
        tools = self.fetch_refused(archive, "unsafe archive member")
        self.assertFalse((self.base / "escape").exists())
        self.assert_not_installed(tools)

    def test_fetch_refuses_absolute_member(self) -> None:
        archive = self.make_tarball(
            files={"jscpd": b"binary\n"},
            absolute=[str(self.base / "absolute-escape")],
        )
        tools = self.fetch_refused(archive, "unsafe archive member")
        self.assertFalse((self.base / "absolute-escape").exists())
        self.assert_not_installed(tools)

    def test_fetch_refuses_symlink_member(self) -> None:
        archive = self.make_tarball(
            files={"jscpd": b"binary\n"},
            links={"linked": "/etc/passwd"},
        )
        tools = self.fetch_refused(archive, "is a link")
        self.assert_not_installed(tools)

    def test_fetch_refuses_non_regular_member(self) -> None:
        archive = self.base / "fifo.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            content = b"#!/bin/sh\necho fake\n"
            member = tarfile.TarInfo("jscpd")
            member.size = len(content)
            member.mode = 0o755
            tar.addfile(member, io.BytesIO(content))
            fifo = tarfile.TarInfo("pipe")
            fifo.type = tarfile.FIFOTYPE
            tar.addfile(fifo)
        tools = self.fetch_refused(archive, "not a regular file")
        self.assert_not_installed(tools)

    def test_fetch_keeps_an_existing_install(self) -> None:
        archive = self.make_tarball()
        tools = self.base / "tools"
        destination = tools / f"jscpd-{VERSION}"
        destination.mkdir(parents=True)
        binary = destination / "jscpd"
        binary.write_text("#!/bin/sh\necho fake\n", encoding="utf-8")
        binary.chmod(0o755)
        (destination / "LICENSE").write_text("MIT\n", encoding="utf-8")
        lock = self.write_lock(
            (self.base / "missing.tar.gz").as_uri(),
            "0" * 64,
            payload=self.archive_payload(archive),
        )
        result = self.fetch(lock, tools)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(
            binary.read_text(encoding="utf-8"), "#!/bin/sh\necho fake\n"
        )
        self.assertIn("already installed", result.stdout)

    def test_fetch_replaces_an_existing_broken_install(self) -> None:
        archive = self.make_tarball()
        tools = self.base / "tools"
        destination = tools / f"jscpd-{VERSION}"
        destination.mkdir(parents=True)
        stale = destination / "stale.txt"
        stale.write_text("stale\n", encoding="utf-8")
        stale_binary = destination / "jscpd"
        stale_binary.write_text("stale binary\n", encoding="utf-8")
        lock = self.write_lock(
            archive.as_uri(),
            self.sha256(archive),
            payload=self.archive_payload(archive),
        )
        result = self.fetch(lock, tools)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse(stale.exists())
        self.assertEqual(
            stale_binary.read_text(encoding="utf-8"),
            "#!/bin/sh\necho fake\n",
        )

    def test_fetch_allows_directory_members_and_nested_binary(self) -> None:
        archive = self.make_tarball(
            files={"pkg/jscpd": b"#!/bin/sh\necho nested\n"},
            directories=["pkg"],
        )
        lock = self.write_lock(
            archive.as_uri(),
            self.sha256(archive),
            binary="pkg/jscpd",
            payload=self.archive_payload(archive, binary="pkg/jscpd"),
        )
        tools = self.base / "tools"
        result = self.fetch(lock, tools)
        self.assertEqual(result.returncode, 0, output(result))
        binary = tools / f"jscpd-{VERSION}" / "pkg" / "jscpd"
        self.assertTrue(binary.is_file())

    def test_fetch_uses_the_default_tools_directory(self) -> None:
        archive = self.make_tarball()
        lock = self.write_lock(
            archive.as_uri(),
            self.sha256(archive),
            payload=self.archive_payload(archive),
        )
        result = self.run_qg(
            "tools", "fetch", "--lock", str(lock), env={}
        )
        self.assertEqual(result.returncode, 0, output(result))
        binary = (
            self.home
            / ".local/share/code-quality-gate/tools"
            / f"jscpd-{VERSION}/jscpd"
        )
        self.assertTrue(binary.is_file(), output(result))

    def test_fetch_download_failure_installs_nothing(self) -> None:
        lock = self.write_lock(
            (self.base / "missing.tar.gz").as_uri(), "0" * 64
        )
        tools = self.base / "tools"
        result = self.fetch(lock, tools)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("download", text)
        self.assert_not_installed(tools)

    def test_fetch_missing_lock_exits_2(self) -> None:
        result = self.run_qg(
            "tools",
            "fetch",
            "--lock",
            str(self.base / "missing-lock.toml"),
            env={"QG_TOOLS_DIR": str(self.base / "tools")},
        )
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("missing-lock.toml", text)
        self.assertIn("missing", text)

    def test_fetch_invalid_lock_toml_exits_2(self) -> None:
        lock = self.base / "lock.toml"
        lock.write_text("[jscpd\n", encoding="utf-8")
        result = self.fetch(lock, self.base / "tools")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("lock.toml", text)
        self.assertIn("expected valid TOML", text)

    def test_fetch_unsafe_binary_path_exits_2(self) -> None:
        lock = self.write_lock(
            "file:///tmp/x.tar.gz", "0" * 64, binary="../jscpd"
        )
        result = self.fetch(lock, self.base / "tools")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("jscpd.binary", text)
        self.assertIn("safe relative path", text)

    def test_fetch_rejects_invalid_tool_name_and_version(self) -> None:
        cases = [
            ("../jscpd", VERSION, "tool name matching"),
            ("bad/name", VERSION, "tool name matching"),
            ("jscpd", "../9.9.9", "jscpd.version"),
            ("jscpd", "bad/version", "jscpd.version"),
        ]
        for name, version, needle in cases:
            with self.subTest(name=name, version=version):
                lock = self.base / "lock.toml"
                lock.write_text(
                    f'["{name}"]\n'
                    f'version = "{version}"\n'
                    'url = "file:///tmp/x.tar.gz"\n'
                    f'sha256 = "{"0" * 64}"\n'
                    'binary = "jscpd"\n',
                    encoding="utf-8",
                )
                result = self.fetch(lock, self.base / "tools")
                text = output(result)
                self.assertEqual(result.returncode, 2, text)
                self.assertIn(needle, text)
                self.assertIn("[A-Za-z0-9]", text)

    def test_fetch_rejects_unknown_lock_keys(self) -> None:
        lock = self.write_lock("file:///tmp/x.tar.gz", "0" * 64)
        lock.write_text(
            lock.read_text(encoding="utf-8")
            + 'binary_sha256 = "ignored"\n',
            encoding="utf-8",
        )
        result = self.fetch(lock, self.base / "tools")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("binary_sha256", text)
        self.assertIn("allowed keys", text)

    def test_fetch_destination_outside_the_tools_directory_is_refused(self) -> None:
        archive = self.make_tarball()
        lock = self.write_lock(archive.as_uri(), self.sha256(archive))
        tools = self.base / "tools"
        outside = self.base / "outside"
        outside.mkdir()
        sentinel = outside / "keep.txt"
        sentinel.write_text("keep\n", encoding="utf-8")
        tools.mkdir()
        (tools / f"jscpd-{VERSION}").symlink_to(outside)
        result = self.fetch(lock, tools)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("outside", text)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep\n")

    def test_fetch_invalid_lock_exits_2(self) -> None:
        lock = self.base / "lock.toml"
        lock.write_text('[jscpd]\nversion = "9.9.9"\n', encoding="utf-8")
        result = self.fetch(lock, self.base / "tools")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("jscpd.url", text)
        self.assertIn("missing", text)

    def test_fetch_lock_missing_required_field_exits_2(self) -> None:
        fields = {
            "version": '"9.9.9"',
            "url": '"file:///tmp/x.tar.gz"',
            "sha256": '"' + "0" * 64 + '"',
            "payload_sha256": '"' + "0" * 64 + '"',
            "binary": '"jscpd"',
        }
        lock = self.base / "lock.toml"
        for missing in fields:
            with self.subTest(missing=missing):
                lines = ["[jscpd]"]
                lines.extend(
                    f"{key} = {value}"
                    for key, value in fields.items()
                    if key != missing
                )
                lock.write_text("\n".join(lines) + "\n", encoding="utf-8")
                result = self.fetch(lock, self.base / "tools")
                text = output(result)
                self.assertEqual(result.returncode, 2, text)
                self.assertIn(f"jscpd.{missing}", text)
                self.assertIn("missing", text)

    def test_fetch_archive_without_binary_installs_nothing(self) -> None:
        archive = self.make_tarball(files={"LICENSE": b"MIT\n"})
        tools = self.fetch_refused(archive, "does not contain 'jscpd'")
        self.assert_not_installed(tools)

    def test_fetch_lock_without_payload_digest_exits_2(self) -> None:
        lock = self.write_lock(
            "file:///tmp/x.tar.gz", "0" * 64, include_payload=False
        )
        result = self.fetch(lock, self.base / "tools")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("jscpd.payload_sha256", text)
        self.assertIn("missing", text)

    def test_fetch_refuses_payload_mismatch_and_installs_nothing(self) -> None:
        archive = self.make_tarball()
        lock = self.write_lock(
            archive.as_uri(), self.sha256(archive), payload="0" * 64
        )
        tools = self.base / "tools"
        result = self.fetch(lock, tools)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("payload sha256 mismatch", text)
        self.assertIn("0" * 64, text)
        self.assertIn("nothing installed", text)
        self.assert_not_installed(tools)
        self.assertEqual(list(tools.iterdir()), [])

    def test_fetch_bad_sha_format_exits_2(self) -> None:
        lock = self.write_lock("file:///tmp/x.tar.gz", "abc")
        result = self.fetch(lock, self.base / "tools")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("jscpd.sha256", text)
        self.assertIn("64-character", text)

    def test_fetch_wheel_extracts_the_zip(self) -> None:
        wheel = self.make_wheel()
        lock = self.write_lock(
            wheel.as_uri(),
            self.sha256(wheel),
            binary="pkg/__init__.py",
            archive_format="wheel",
            payload=self.archive_payload(
                wheel, binary="pkg/__init__.py", archive_format="wheel"
            ),
        )
        tools = self.base / "tools"
        result = self.fetch(lock, tools)
        self.assertEqual(result.returncode, 0, output(result))
        installed = tools / f"jscpd-{VERSION}" / "pkg" / "__init__.py"
        self.assertTrue(installed.is_file())
        self.assertEqual(
            installed.read_text(encoding="utf-8"), "VALUE = 1\n"
        )
        self.assertTrue(
            (tools / f"jscpd-{VERSION}" / "pkg" / "mod.py").is_file()
        )

    def test_fetch_wheel_with_wrong_hash_installs_nothing(self) -> None:
        wheel = self.make_wheel()
        lock = self.write_lock(
            wheel.as_uri(),
            "0" * 64,
            binary="pkg/__init__.py",
            archive_format="wheel",
        )
        tools = self.base / "tools"
        result = self.fetch(lock, tools)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("sha256 mismatch", text)
        self.assert_not_installed(tools)

    def test_fetch_wheel_refuses_path_traversal_member(self) -> None:
        wheel = self.make_wheel(
            files={
                "../escape": b"evil\n",
                "pkg/__init__.py": b"VALUE = 1\n",
            }
        )
        self.fetch_wheel_refused(wheel, "unsafe archive member")
        self.assertFalse((self.base / "escape").exists())

    def test_fetch_wheel_refuses_absolute_member(self) -> None:
        wheel = self.make_wheel(
            files={
                "/absolute-escape": b"evil\n",
                "pkg/__init__.py": b"VALUE = 1\n",
            }
        )
        self.fetch_wheel_refused(wheel, "unsafe archive member")

    def test_fetch_wheel_refuses_symlink_member(self) -> None:
        wheel = self.make_wheel(links={"pkg/link": "/etc/passwd"})
        self.fetch_wheel_refused(wheel, "is a link")

    def test_fetch_rejects_unknown_archive_format(self) -> None:
        lock = self.write_lock(
            "file:///tmp/x.zip",
            "0" * 64,
            archive_format="zip",
        )
        result = self.fetch(lock, self.base / "tools")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("jscpd.format", text)
        self.assertIn("one of tar, wheel", text)

    def test_tools_path_prints_the_default_path(self) -> None:
        tools = self.base / "tools"
        binary = tools / "jscpd-5.4.1" / "jscpd"
        binary.parent.mkdir(parents=True)
        binary.write_text("binary\n", encoding="utf-8")
        result = self.run_qg(
            "tools", "path", "jscpd", env={"QG_TOOLS_DIR": str(tools)}
        )
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(result.stdout.strip(), str(binary))

    def test_tools_path_prints_the_path_when_not_installed(self) -> None:
        tools = self.base / "missing-tools"
        result = self.run_qg(
            "tools", "path", "jscpd", env={"QG_TOOLS_DIR": str(tools)}
        )
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(
            result.stdout.strip(),
            str(tools / "jscpd-5.4.1" / "jscpd"),
        )

    def test_tools_path_prints_the_ruff_path(self) -> None:
        tools = self.base / "tools"
        result = self.run_qg(
            "tools", "path", "ruff", env={"QG_TOOLS_DIR": str(tools)}
        )
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(
            result.stdout.strip(),
            str(
                tools
                / f"ruff-{RUFF_VERSION}"
                / "ruff-x86_64-unknown-linux-gnu"
                / "ruff"
            ),
        )

    def test_tools_path_unknown_name_exits_2(self) -> None:
        result = self.run_qg("tools", "path", "mystery")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("unknown tool 'mystery'", text)


class ToolUseVerificationTests(FixtureCase):
    def unsupported_check(
        self, result: object, document: dict, *needles: str
    ) -> dict:
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "smoke")
        self.assertEqual(check["outcome"], "unsupported")
        for needle in needles:
            self.assertIn(needle, check["reason"])
        return check

    def ruff_tool(self) -> tuple[Path, Path, Path, Path, str]:
        tools = self.base / "tools"
        installation = tools / f"ruff-{RUFF_VERSION}"
        destination = installation / "ruff-x86_64-unknown-linux-gnu"
        destination.mkdir(parents=True)
        sentinel = self.base / "ruff-ran"
        binary = destination / "ruff"
        binary.write_text(
            f"#!/bin/sh\necho ran > {sentinel}\necho 1\n",
            encoding="utf-8",
        )
        binary.chmod(0o755)
        self.fixture_gate()
        expected = self.payload_digest(installation)
        self.set_lock_field("ruff", "payload_sha256", expected)
        self.write_config(
            BASE_CONFIG.replace(
                'run = ["python3", "-c", "print(1)"]',
                'run = ["{tool:ruff}", "--version"]',
            )
        )
        return tools, installation, binary, sentinel, expected

    def test_tampered_ruff_is_unsupported_before_it_runs(self) -> None:
        tools, installation, binary, sentinel, expected = self.ruff_tool()
        binary.write_text(binary.read_text() + "# tampered\n", encoding="utf-8")
        actual = self.payload_digest(installation)
        result, document = self.run_json(
            env={"QG_TOOLS_DIR": str(tools)}
        )
        self.unsupported_check(
            result,
            document,
            f"ruff {RUFF_VERSION}",
            str(installation),
            expected,
            actual,
        )
        self.assertFalse(sentinel.exists())

    def test_unreadable_tool_entry_is_unsupported_before_it_runs(self) -> None:
        _tools, installation, binary, _sentinel, expected = self.ruff_tool()
        destination = binary.parent
        scandir = os.scandir

        def unreadable(path: object) -> object:
            if Path(path) == destination:
                raise PermissionError("Permission denied")
            return scandir(path)

        with lock_override(
            self.gate / "tools.lock.toml"
        ), mock.patch(
            "quality_gate.tools.os.scandir", side_effect=unreadable
        ):
            with self.assertRaises(UnsupportedError) as raised:
                verify_tool_directory("ruff", installation)
        message = str(raised.exception)
        for needle in (
            f"ruff {RUFF_VERSION}",
            str(installation),
            str(destination),
            expected,
            "Permission denied",
            "nothing from this install runs",
        ):
            self.assertIn(needle, message)

    def test_modified_coverage_is_unsupported_before_it_runs(self) -> None:
        version = "7.16.2"
        tools = self.base / "tools"
        destination = tools / f"coverage-{version}"
        package = destination / "coverage"
        package.mkdir(parents=True)
        sentinel = self.base / "coverage-imported"
        init = package / "__init__.py"
        init.write_text(
            f"open({str(sentinel)!r}, 'w').write('imported\\n')\n",
            encoding="utf-8",
        )
        self.fixture_gate()
        expected = self.payload_digest(destination)
        self.set_lock_field("coverage", "payload_sha256", expected)
        init.write_text(init.read_text() + "TAMPERED = 1\n", encoding="utf-8")
        actual = self.payload_digest(destination)
        probe = self.add_file(
            "tests/probe.py",
            f"open({str(sentinel)!r}, 'w').write('ran\\n')\n",
        )
        self.write_config(
            BASE_CONFIG.replace(
                'adapter = "command"', 'adapter = "python_tests"'
            )
            .replace(
                'run = ["python3", "-c", "print(1)"]',
                f"run = {json.dumps(['{python}', 'tests/probe.py'])}",
            )
            .replace(
                "tests_pattern = '(\\d+)'",
                f"tests_pattern = {json.dumps(r'^Ran (\\d+) tests?')}",
            )
        )
        result, document = self.run_json(
            env={"QG_TOOLS_DIR": str(tools)}
        )
        self.unsupported_check(
            result,
            document,
            "coverage 7.16.2",
            str(destination),
            expected,
            actual,
        )
        self.assertFalse(sentinel.exists())
        self.assertTrue(probe.is_file())


class PayloadDigestTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="qg-payload-")
        self.addCleanup(self._temporary.cleanup)
        self.base = Path(self._temporary.name)
        self.root = self.base / "tree"
        (self.root / "pkg").mkdir(parents=True)
        (self.root / "pkg" / "tool").write_text("one\n", encoding="utf-8")
        (self.root / "pkg" / "tool").chmod(0o644)
        (self.root / "README").write_text("readme\n", encoding="utf-8")
        os.symlink("pkg/tool", self.root / "link")

    def test_digest_is_stable_across_runs(self) -> None:
        self.assertEqual(payload_digest(self.root), payload_digest(self.root))

    def test_digest_matches_a_fixed_oracle(self) -> None:
        root = self.base / "oracle"
        (root / "z").mkdir(parents=True)
        (root / "z" / "run").write_text("#!/bin/sh\n", encoding="utf-8")
        (root / "z" / "run").chmod(0o755)
        (root / "b").write_text("b\n", encoding="utf-8")
        (root / "a").write_text("a\n", encoding="utf-8")
        (root / "café").write_text("unicode\n", encoding="utf-8")
        os.symlink("a", root / "link")
        self.assertEqual(
            payload_digest(root),
            "e8cc7b3130018e2512cf76bb62e016b1f53a4e28ee6dff70162937f15ad08d11",
        )

    def test_one_changed_byte_changes_the_digest(self) -> None:
        before = payload_digest(self.root)
        (self.root / "pkg" / "tool").write_text("two\n", encoding="utf-8")
        self.assertNotEqual(before, payload_digest(self.root))

    def test_a_flipped_executable_bit_changes_the_digest(self) -> None:
        before = payload_digest(self.root)
        (self.root / "pkg" / "tool").chmod(0o755)
        self.assertNotEqual(before, payload_digest(self.root))

    def test_an_added_file_changes_the_digest(self) -> None:
        before = payload_digest(self.root)
        (self.root / "pkg" / "extra").write_text("extra\n", encoding="utf-8")
        self.assertNotEqual(before, payload_digest(self.root))

    def test_a_removed_file_changes_the_digest(self) -> None:
        before = payload_digest(self.root)
        (self.root / "README").unlink()
        self.assertNotEqual(before, payload_digest(self.root))

    def test_a_retargeted_symlink_changes_the_digest(self) -> None:
        before = payload_digest(self.root)
        (self.root / "link").unlink()
        os.symlink("README", self.root / "link")
        self.assertNotEqual(before, payload_digest(self.root))

    def test_a_fifo_makes_the_tree_invalid(self) -> None:
        os.mkfifo(self.root / "pipe")
        with self.assertRaises(PayloadError) as raised:
            payload_digest(self.root)
        self.assertIn("pipe", str(raised.exception))
        self.assertIn("regular file, directory or symlink", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
