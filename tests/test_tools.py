"""Tests for pinned tool fetching and path resolution."""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
import unittest
from pathlib import Path

from support import FixtureCase, output

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

    def sha256(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def write_lock(
        self,
        url: str,
        digest: str,
        *,
        version: str = VERSION,
        binary: str = "jscpd",
        path: Path | None = None,
    ) -> Path:
        lock = path or (self.base / "lock.toml")
        lock.write_text(
            "[jscpd]\n"
            f'version = "{version}"\n'
            f"url = {json.dumps(url)}\n"
            f'sha256 = "{digest}"\n'
            f'binary = "{binary}"\n',
            encoding="utf-8",
        )
        return lock

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

    def fetch_ok(self, archive: Path) -> tuple[Path, object]:
        lock = self.write_lock(archive.as_uri(), self.sha256(archive))
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
        tools = self.base / "tools"
        destination = tools / f"jscpd-{VERSION}"
        destination.mkdir(parents=True)
        binary = destination / "jscpd"
        binary.write_text("existing binary\n", encoding="utf-8")
        lock = self.write_lock(
            (self.base / "missing.tar.gz").as_uri(), "0" * 64
        )
        result = self.fetch(lock, tools)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(binary.read_text(encoding="utf-8"), "existing binary\n")
        self.assertIn("already installed", result.stdout)

    def test_fetch_allows_directory_members_and_nested_binary(self) -> None:
        archive = self.make_tarball(
            files={"pkg/jscpd": b"#!/bin/sh\necho nested\n"},
            directories=["pkg"],
        )
        lock = self.write_lock(
            archive.as_uri(),
            self.sha256(archive),
            binary="pkg/jscpd",
        )
        tools = self.base / "tools"
        result = self.fetch(lock, tools)
        self.assertEqual(result.returncode, 0, output(result))
        binary = tools / f"jscpd-{VERSION}" / "pkg" / "jscpd"
        self.assertTrue(binary.is_file())

    def test_fetch_uses_the_default_tools_directory(self) -> None:
        archive = self.make_tarball()
        lock = self.write_lock(archive.as_uri(), self.sha256(archive))
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

    def test_fetch_bad_sha_format_exits_2(self) -> None:
        lock = self.write_lock("file:///tmp/x.tar.gz", "abc")
        result = self.fetch(lock, self.base / "tools")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("jscpd.sha256", text)
        self.assertIn("64-character", text)

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

    def test_tools_path_unknown_name_exits_2(self) -> None:
        result = self.run_qg("tools", "path", "mystery")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("unknown tool 'mystery'", text)


if __name__ == "__main__":
    unittest.main()
