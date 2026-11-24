"""Tests for pinned tool fetching and path resolution."""
from __future__ import annotations

import contextlib
import ctypes
import hashlib
import io
import json
import os
import pwd
import random
import resource
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from collections.abc import Callable
from pathlib import Path
from unittest import mock

from support import BASE_CONFIG, GATE, RUFF_VERSION, FixtureCase, output

from quality_gate import tools as gate_tools
from quality_gate.cli import main
from quality_gate.payload import PayloadError, payload_digest
from quality_gate.policy import GateError, UnsupportedError
from quality_gate.tools import (
    Tool,
    _extract_tar,
    _extract_wheel,
    _pinned_tool,
    _wheel_member_path,
    lock_override,
    verify_tool_directory,
)

VERSION = "9.9.9"
CONDA_HOOKS = tuple(
    f"{directory}/.example-{event}.{extension}"
    for directory, extension in (("bin", "sh"), ("Scripts", "bat"))
    for event in ("pre-link", "post-link", "pre-unlink")
)


def restore_owner_write(directory: Path) -> None:
    """Restore the owner's write bit on a fetched payload worth changing."""
    for path in [directory, *directory.rglob("*")]:
        if path.is_symlink():
            continue
        mode = path.lstat().st_mode
        path.chmod(stat.S_IMODE(mode) | stat.S_IWUSR)


def child_permissions(base: Path) -> dict[str, object]:
    """Run the import child without root's bypass of the payload's modes."""
    if os.geteuid() != 0:
        return {}
    account = pwd.getpwnam("nobody")
    base.chmod(0o755)
    return {
        "user": account.pw_uid,
        "group": account.pw_gid,
        "extra_groups": [],
    }


class ToolsTests(FixtureCase):
    def test_repository_lock_pins_shfmt_conda_artifact(self) -> None:
        with lock_override(GATE / "tools.lock.toml"):
            _, tool = _pinned_tool("shfmt")

        self.assertEqual(tool.version, "3.14.1")
        self.assertEqual(tool.format, "conda")
        self.assertEqual(tool.binary, "bin/shfmt")
        self.assertEqual(
            tool.url, "https://conda.anaconda.org/conda-forge/linux-64/go-shfmt-3.14.1-hfc2019e_0.conda"
        )
        self.assertEqual(
            tool.sha256, "0cc0a5c62bba143b540a5f266fc3bc826ce784bc244be957f3a5af77c65d2011"
        )
        self.assertEqual(
            tool.payload_sha256,
            "25a74fe433754f10a50a4ee05aec3ccf96c09545b08f94d2595a895f8e36711e",
        )

    def make_tarball(
        self,
        name: str = "tool.tar.gz",
        *,
        files: dict[str, bytes] | None = None,
        links: dict[str, str] | None = None,
        hardlinks: dict[str, str] | None = None,
        devices: list[str] | None = None,
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
            for member, target in (hardlinks or {}).items():
                info = tarfile.TarInfo(member)
                info.type = tarfile.LNKTYPE
                info.linkname = target
                archive.addfile(info)
            for member in devices or []:
                info = tarfile.TarInfo(member)
                info.type = tarfile.CHRTYPE
                info.devmajor = 1
                info.devminor = 3
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
        modes: dict[str, int] | None = None,
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
                mode = (modes or {}).get(
                    member, stat.S_IFREG | 0o644
                )
                info.external_attr = mode << 16
                archive.writestr(info, content)
            for member, target in (links or {}).items():
                info = zipfile.ZipInfo(member)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, target)
        return path

    def conda_members(self) -> dict[str, bytes]:
        script = f"#!/bin/sh\ntouch '{self.base / 'script-ran'}'\n".encode()
        contents = {
            "bin/example": (b"#!/bin/sh\necho fake\n", 0o755),
            "share/data": (random.Random(0).randbytes(160_000), 0o644),
        }
        expected = self.base / "expected"
        for name, (content, mode) in contents.items():
            path = expected / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(mode)
        return {
            "metadata.json": b'{"conda_pkg_format_version": 2}',
            "info-example-1-0.tar.zst": self.conda_tar({
                "info/index.json": (b'{"name":"example"}', 0o644),
                "info/recipe/build.sh": (script, 0o755),
            }),
            "pkg-example-1-0.tar.zst": self.conda_tar({
                **contents, **dict.fromkeys(CONDA_HOOKS, (script, 0o755)),
            }),
        }

    def conda_tar(
        self, files: dict[str, tuple[bytes, int]], extra: tarfile.TarInfo | None = None
    ) -> bytes:
        return self.conda_compress(self.raw_tar(files, extra))

    def raw_tar(
        self, files: dict[str, tuple[bytes, int]], extra: tarfile.TarInfo | None = None
    ) -> bytes:
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:") as archive:
            for name, (content, mode) in files.items():
                member = tarfile.TarInfo(name)
                member.mode, member.size = mode, len(content)
                archive.addfile(member, io.BytesIO(content))
            if extra is not None:
                archive.addfile(extra)
        return data.getvalue()

    def conda_compress(self, raw: bytes) -> bytes:
        zstd = ctypes.CDLL("libzstd.so.1")
        zstd.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
        zstd.ZSTD_compressBound.restype = ctypes.c_size_t
        zstd.ZSTD_compress.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_int,
        ]
        zstd.ZSTD_compress.restype = ctypes.c_size_t
        compressed = ctypes.create_string_buffer(zstd.ZSTD_compressBound(len(raw)))
        size = zstd.ZSTD_compress(compressed, len(compressed), raw, len(raw), 1)
        self.assertLessEqual(size, len(compressed))
        return compressed[:size]

    def make_conda(
        self, members: dict[str, bytes], extra: str | zipfile.ZipInfo | None = None
    ) -> Path:
        path = self.base / "example-1-0.conda"
        with zipfile.ZipFile(path, "w") as archive:
            for name, content in members.items():
                archive.writestr(name, content)
            if extra is not None:
                archive.writestr(extra, b"extra member")
        return path

    def conda_lock(self, package: Path, **overrides: str) -> Path:
        fields = {
            "digest": self.sha256(package),
            "payload": payload_digest(self.base / "expected"),
        }
        fields.update(overrides)
        return self.write_lock(
            package.as_uri(), binary="bin/example", archive_format="conda", **fields
        )

    def sha256(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def archive_lock(self, archive: Path) -> Path:
        return self.write_lock(
            archive.as_uri(),
            self.sha256(archive),
            payload=self.archive_payload(archive),
        )

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
        lines.append(f"binary = {json.dumps(binary)}")
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

    def check_install(self, lock: Path, tools: Path) -> subprocess.CompletedProcess[str]:
        with mock.patch(
            "urllib.request.urlopen",
            side_effect=AssertionError("offline check attempted a download"),
        ) as download:
            result = self.fetch(lock, tools, "--check")
        download.assert_not_called()
        return result

    def seed_check_install(self, tools: Path) -> Path:
        directory = tools / f"jscpd-{VERSION}"
        directory.mkdir(parents=True)
        binary = directory / "jscpd"
        binary.write_text(f"#!/bin/sh\ntouch '{self.base / 'tool-ran'}'\n", encoding="utf-8")
        binary.chmod(0o755)
        (directory / "LICENSE").write_bytes(b"MIT\n")
        return directory

    def check_lock(self, directory: Path, path: Path | None = None) -> Path:
        return self.write_lock(
            (self.base / "absent.tar.gz").as_uri(), "0" * 64,
            payload=payload_digest(directory), path=path,
        )

    def fetch_refused(self, archive: Path, message: str) -> Path:
        lock = self.write_lock(archive.as_uri(), self.sha256(archive))
        tools = self.base / "tools"
        result = self.fetch(lock, tools)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertEqual(
            result.stderr,
            f"tools: jscpd {VERSION}: {message}\n",
        )
        return tools

    def assert_not_installed(self, tools: Path) -> None:
        self.assertFalse((tools / f"jscpd-{VERSION}").exists())

    def fetch_wheel_refused(self, wheel: Path, message: str) -> None:
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
        self.assertEqual(
            result.stderr,
            f"tools: jscpd {VERSION}: {message}\n",
        )
        self.assert_not_installed(tools)

    def extract_refused(
        self, extractor, archive: Path, message: str, outside: Path
    ) -> None:
        destination = self.base / "destination"
        destination.mkdir(exist_ok=True)
        tool = Tool(
            name="jscpd",
            version=VERSION,
            url=archive.as_uri(),
            sha256="0" * 64,
            payload_sha256="0" * 64,
            binary="jscpd",
        )
        with self.assertRaises(GateError) as raised:
            extractor(archive, destination, tool)
        self.assertEqual(
            str(raised.exception),
            f"tools: jscpd {VERSION}: {message}",
        )
        self.assertFalse(outside.exists())
        self.assertEqual(list(destination.rglob("*")), [])

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

    def test_fetch_makes_the_payload_read_only(self) -> None:
        archive = self.make_tarball()
        tools, _result = self.fetch_ok(archive)
        installation = tools / f"jscpd-{VERSION}"
        for path in [installation, *installation.rglob("*")]:
            self.assertFalse(path.lstat().st_mode & 0o222, str(path))
        self.assertEqual(
            self.payload_digest(installation), self.archive_payload(archive)
        )

    def test_an_import_cannot_write_into_a_fetched_payload(self) -> None:
        wheel = self.make_wheel()
        payload = self.archive_payload(
            wheel, binary="pkg/__init__.py", archive_format="wheel"
        )
        lock = self.write_lock(
            wheel.as_uri(),
            self.sha256(wheel),
            binary="pkg/__init__.py",
            archive_format="wheel",
            payload=payload,
        )
        tools = self.base / "tools"
        previous_umask = os.umask(0o022)
        try:
            result = self.fetch(lock, tools)
        finally:
            os.umask(previous_umask)
        self.assertEqual(result.returncode, 0, output(result))
        installation = tools / f"jscpd-{VERSION}"
        entries = sorted(
            str(path.relative_to(installation))
            for path in installation.rglob("*")
        )
        child = subprocess.run(
            [
                sys.executable,
                "-E",
                "-s",
                "-c",
                "import sys; assert not sys.dont_write_bytecode; import pkg.mod",
            ],
            cwd=installation,
            env=self.env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            **child_permissions(self.base),
        )
        self.assertEqual(child.returncode, 0, output(child))
        self.assertEqual(
            sorted(
                str(path.relative_to(installation))
                for path in installation.rglob("*")
            ),
            entries,
        )
        self.assertEqual(self.payload_digest(installation), payload)
        with lock_override(lock):
            self.assertEqual(
                verify_tool_directory("jscpd", installation), installation
            )

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
        tools = self.fetch_refused(
            archive,
            "unsafe archive member '../escape'; nothing installed",
        )
        self.assertFalse((self.base / "escape").exists())
        self.assert_not_installed(tools)

    def test_fetch_refuses_absolute_member(self) -> None:
        outside = self.base / "absolute-escape"
        archive = self.make_tarball(
            files={"jscpd": b"binary\n"},
            absolute=[str(outside)],
        )
        tools = self.fetch_refused(
            archive,
            f"unsafe archive member {str(outside)!r}; nothing installed",
        )
        self.assertFalse(outside.exists())
        self.assert_not_installed(tools)

    def test_fetch_refuses_symlink_member(self) -> None:
        outside = self.base / "symlink-escape"
        archive = self.make_tarball(
            files={"jscpd": b"binary\n"},
            links={"linked": str(outside)},
        )
        tools = self.fetch_refused(
            archive,
            "unsafe archive member 'linked' is a link; "
            "nothing installed",
        )
        self.assertFalse(outside.exists())
        self.assert_not_installed(tools)

    def test_fetch_refuses_hardlink_member(self) -> None:
        outside = self.base / "hardlink-escape"
        archive = self.make_tarball(
            files={"jscpd": b"binary\n"},
            hardlinks={"linked": str(outside)},
        )
        tools = self.fetch_refused(
            archive,
            "unsafe archive member 'linked' is a link; "
            "nothing installed",
        )
        self.assertFalse(outside.exists())
        self.assert_not_installed(tools)

    def test_fetch_refuses_device_member(self) -> None:
        archive = self.make_tarball(
            files={"jscpd": b"binary\n"},
            devices=["device"],
        )
        tools = self.fetch_refused(
            archive,
            "unsafe archive member 'device' is not a regular file; "
            "nothing installed",
        )
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
        tools = self.fetch_refused(
            archive,
            "unsafe archive member 'pipe' is not a regular file; "
            "nothing installed",
        )
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
        payload = self.archive_payload(archive)
        lock = self.write_lock(
            (self.base / "missing.tar.gz").as_uri(),
            "0" * 64,
            payload=payload,
        )
        download = mock.Mock()
        with mock.patch("quality_gate.tools._download", download):
            result = self.fetch(lock, tools)
        self.assertEqual(result.returncode, 0, output(result))
        download.assert_not_called()
        self.assertEqual(
            binary.read_text(encoding="utf-8"), "#!/bin/sh\necho fake\n"
        )
        self.assertIn("already installed", result.stdout)
        self.assertIn("read-only", result.stdout)
        for path in [destination, *destination.rglob("*")]:
            self.assertFalse(path.lstat().st_mode & 0o222, str(path))
        self.assertEqual(self.payload_digest(destination), payload)

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

    def test_fetch_replaces_an_existing_install_file(self) -> None:
        archive = self.make_tarball()
        destination = self.base / "tools" / f"jscpd-{VERSION}"
        destination.parent.mkdir()
        destination.write_text("stale\n", encoding="utf-8")
        _tools, _result = self.fetch_ok(archive)
        self.assertEqual(
            (destination / "jscpd").read_text(encoding="utf-8"),
            "#!/bin/sh\necho fake\n",
        )

    def test_fetch_names_the_install_path_when_removal_fails(self) -> None:
        archive = self.make_tarball()
        tools = self.base / "tools"
        destination = tools / f"jscpd-{VERSION}"
        destination.mkdir(parents=True)
        (destination / "stale.txt").write_text("stale\n", encoding="utf-8")
        lock = self.write_lock(
            archive.as_uri(),
            self.sha256(archive),
            payload=self.archive_payload(archive),
        )
        with mock.patch(
            "quality_gate.tools._make_directories_writable",
            side_effect=PermissionError("denied"),
        ):
            result = self.fetch(lock, tools)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn(f"cannot remove install at {destination}", text)
        self.assertIn("denied", text)

    def test_fetch_names_the_payload_path_when_hardening_fails(self) -> None:
        archive = self.make_tarball()
        lock = self.archive_lock(archive)
        tools = self.base / "tools"
        chmod = os.chmod

        def fail_on_build(path: object, mode: int) -> None:
            if Path(path).name == "build":
                raise PermissionError("denied")
            chmod(path, mode)

        with mock.patch(
            "quality_gate.tools.os.chmod", side_effect=fail_on_build
        ):
            result = self.fetch(lock, tools)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("cannot make payload at", text)
        self.assertIn("build", text)
        self.assertIn("denied", text)
        self.assert_not_installed(tools)

    def test_fetch_replaces_a_read_only_install_with_a_different_payload(
        self,
    ) -> None:
        first = self.make_tarball(
            files={
                "jscpd": b"#!/bin/sh\necho first\n",
                "LICENSE": b"first\n",
            }
        )
        tools, _result = self.fetch_ok(first)
        installation = tools / f"jscpd-{VERSION}"
        second = self.make_tarball(
            "second.tar.gz",
            files={
                "jscpd": b"#!/bin/sh\necho second\n",
                "LICENSE": b"second\n",
            },
        )
        payload = self.archive_payload(second)
        lock = self.write_lock(
            second.as_uri(), self.sha256(second), payload=payload
        )
        result = self.fetch(lock, tools)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(
            (installation / "jscpd").read_text(encoding="utf-8"),
            "#!/bin/sh\necho second\n",
        )
        self.assertEqual(self.payload_digest(installation), payload)
        self.assertFalse(installation.stat().st_mode & 0o222)

    def test_fetch_allows_directory_members_and_nested_binary(self) -> None:
        archive = self.make_tarball(
            files={"pkg/jscpd": b"#!/bin/sh\necho nested\n"},
            directories=[".", "pkg"],
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

    def test_fetch_unreadable_lock_exits_2(self) -> None:
        lock = self.base / "lock.toml"
        lock.mkdir()
        result = self.fetch(lock, self.base / "tools")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertEqual(result.stdout, "")
        self.assertIn("expected a readable tool lock file", text)
        self.assertIn(str(lock), text)

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

    def test_fetch_check_verifies_all_tools_offline(self) -> None:
        tools = self.base / "tools"
        directory = self.seed_check_install(tools)
        lock = self.check_lock(directory)
        other = tools / f"second-{VERSION}"
        shutil.copytree(directory, other)
        first = lock.read_text(encoding="utf-8")
        lock.write_text(first + "\n" + first.replace("[jscpd]", "[second]"), encoding="utf-8")

        result = self.check_install(lock, tools)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse((self.base / "tool-ran").exists())
        (other / "LICENSE").unlink()
        result = self.check_install(lock, tools)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn(f"second {VERSION}: payload digest mismatch", result.stderr)

    def test_fetch_check_traverses_search_only_cache_ancestor(self) -> None:
        ancestor = self.base / "search-only"
        tools = ancestor / "tools"
        lock = self.check_lock(self.seed_check_install(tools))
        open_path = os.open

        def search_only(path, flags, *args, **kwargs):
            if path == ancestor.name and os.geteuid() == 0 and not flags & os.O_PATH:
                raise PermissionError("search-only directory")
            return open_path(path, flags, *args, **kwargs)

        ancestor.chmod(0o100)
        try:
            with mock.patch.object(os, "open", new=search_only):
                result = self.check_install(lock, tools)
            self.assertEqual(result.returncode, 0, output(result))
        finally:
            ancestor.chmod(0o700)

    def test_fetch_check_verifies_a_thousand_levels_with_limited_descriptors(self) -> None:
        tools = self.base / "tools"
        directory = self.seed_check_install(tools)
        branches = []
        leaf = directory
        try:
            for _ in range(1000):
                leaf /= "d"
                leaf.mkdir()
                branches.append(leaf)
            (leaf / "data").write_bytes(b"deep payload\n")
            lock = self.check_lock(directory)
            limits = resource.getrlimit(resource.RLIMIT_NOFILE)
            soft, hard = limits
            limit = 64 if soft == resource.RLIM_INFINITY else min(soft, 64)
            resource.setrlimit(resource.RLIMIT_NOFILE, (limit, hard))
            try:
                result = self.check_install(lock, tools)
            finally:
                resource.setrlimit(resource.RLIMIT_NOFILE, limits)
            self.assertEqual(result.returncode, 0, output(result))
        finally:
            (leaf / "data").unlink(missing_ok=True)
            for branch in reversed(branches):
                branch.rmdir()

    def test_fetch_check_reports_missing_install_without_creating_cache(self) -> None:
        lock = self.write_lock("file:///unused", "0" * 64)
        tools = self.base / "tools"
        result = self.check_install(lock, tools)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn(f"is not installed at {tools / f'jscpd-{VERSION}' / 'jscpd'}", result.stderr)
        self.assertFalse(tools.exists())

        directory = self.seed_check_install(tools)
        binary = directory / "jscpd"
        binary.unlink()
        result = self.check_install(lock, tools)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn(f"jscpd {VERSION} is not installed at {binary}", result.stderr)

    def test_fetch_check_reports_payload_mismatch(self) -> None:
        tools = self.base / "tools"
        directory = self.seed_check_install(tools)
        lock = self.check_lock(directory)
        expected = payload_digest(directory)
        binary = directory / "jscpd"
        binary.chmod(0o644)
        actual = payload_digest(directory)
        result = self.check_install(lock, tools)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn(f"jscpd {VERSION}: payload digest mismatch at {directory}", result.stderr)
        self.assertIn(f"expected {expected}, got {actual}", result.stderr)
        self.assertEqual(binary.stat().st_mode & 0o777, 0o644)

    def test_fetch_check_reports_invalid_tree(self) -> None:
        tools = self.base / "tools"
        directory = self.seed_check_install(tools)
        lock = self.check_lock(directory)
        os.mkfifo(directory / "pipe")
        result = self.check_install(lock, tools)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn(f"jscpd {VERSION}: payload tree at {directory} is invalid", result.stderr)
        self.assertIn("is not a regular file, directory or symlink", result.stderr)

        (directory / "pipe").unlink()
        binary = directory / "jscpd"
        binary.unlink()
        binary.mkdir()
        result = self.check_install(lock, tools)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn(f"jscpd {VERSION}: payload tree at {directory} is invalid", result.stderr)
        self.assertIn(f"{binary} is not a regular file", result.stderr)

    def test_fetch_check_reports_install_open_failure(self) -> None:
        tools = self.base / "tools"
        directory = self.seed_check_install(tools)
        lock = self.check_lock(directory)
        open_path = os.open

        def denied(path, flags, *args, **kwargs):
            if path == directory.name and kwargs.get("dir_fd") is not None:
                raise PermissionError("install access denied")
            return open_path(path, flags, *args, **kwargs)

        with mock.patch.object(os, "open", side_effect=denied):
            result = self.check_install(lock, tools)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn(f"jscpd {VERSION}", result.stderr)
        self.assertIn(f"cannot open {directory}", result.stderr)
        self.assertIn("install access denied", result.stderr)

    def test_fetch_check_refuses_matching_tree_outside_cache(self) -> None:
        outside = self.seed_check_install(self.base / "outside")
        lock = self.check_lock(outside)
        tools = self.base / "tools"
        tools.mkdir()
        destination = tools / outside.name
        destination.symlink_to(outside)
        self.assert_check_refuses_symlink(lock, tools, destination)

    def test_fetch_check_hashes_nonbinary_links_as_text(self) -> None:
        tools = self.base / "tools"
        directory = self.seed_check_install(tools)
        external = self.base / "outside"
        external.write_bytes(b"outside")
        link = directory / "external"
        link.symlink_to(external)
        (directory / "loop").symlink_to("loop")
        (directory / "dangling").symlink_to(self.base / "missing")
        lock = self.check_lock(directory)

        external.unlink()
        external.mkdir()
        result = self.check_install(lock, tools)
        self.assertEqual(result.returncode, 0, output(result))

        link.unlink()
        link.symlink_to(self.base / "different")
        result = self.check_install(lock, tools)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn(f"jscpd {VERSION}: payload digest mismatch at {directory}", result.stderr)

    def test_fetch_check_refuses_symlink_binary_components(self) -> None:
        content = b"executable"
        for name in ("jscpd", "usr/bin"):
            with self.subTest(path=name):
                tools = self.base / Path(name).name
                directory = tools / f"jscpd-{VERSION}"
                outside = tools / "sibling"
                outside.mkdir(parents=True)
                external = outside / "example"
                external.write_bytes(content)
                path = directory / name
                path.parent.mkdir(parents=True)
                path.symlink_to(outside if path.name == "bin" else external)
                binary = "usr/bin/example" if path.name == "bin" else "jscpd"
                lock = self.write_lock(
                    "file:///unused", "0" * 64, binary=binary, payload=payload_digest(directory)
                )

                self.assert_check_refuses_symlink(lock, tools, path)

    def assert_check_refuses_symlink(self, lock: Path, tools: Path, path: Path) -> None:
        with mock.patch.object(hashlib, "file_digest", wraps=hashlib.file_digest) as digest:
            result = self.check_install(lock, tools)
        digest.assert_not_called()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn(f"jscpd {VERSION}", result.stderr)
        self.assertIn(str(path), result.stderr)
        self.assertIn("symbolic link", result.stderr)

    def test_fetch_check_refuses_file_swapped_to_symlink_before_open(self) -> None:
        external = self.base / "outside"
        external.write_bytes(b"MIT\n")
        self.assert_check_refuses_swapped_file(
            lambda path: path.symlink_to(external), "without following symbolic links"
        )

    def test_fetch_check_refuses_file_swapped_to_fifo_before_open(self) -> None:
        self.assert_check_refuses_swapped_file(os.mkfifo, "is not a regular file")

    def assert_check_refuses_swapped_file(
        self, replace: Callable[[Path], None], diagnostic: str
    ) -> None:
        tools = self.base / "tools"
        directory = self.seed_check_install(tools)
        path = directory / "LICENSE"
        lock = self.check_lock(directory)
        open_path = os.open

        def replace_before_open(name, flags, *args, **kwargs):
            if name == path.name and kwargs.get("dir_fd") is not None:
                self.assertTrue(flags & os.O_NONBLOCK)
                path.unlink()
                replace(path)
            return open_path(name, flags, *args, **kwargs)

        with mock.patch.object(os, "open", side_effect=replace_before_open):
            result = self.check_install(lock, tools)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn(f"jscpd {VERSION}", result.stderr)
        self.assertIn(str(path), result.stderr)
        self.assertIn(diagnostic, result.stderr)

    def test_fetch_check_rejects_invalid_binary_lock_path(self) -> None:
        tools = self.base / "tools"
        for binary in (
            "bad\0name", "bin\\example", "/outside", "../outside",
            "bin//example", "bin/./example", "bin/../example", "bin/example/",
        ):
            with self.subTest(binary=binary):
                lock = self.write_lock("file:///unused", "0" * 64, binary=binary)
                result = self.check_install(lock, tools)
                self.assertEqual(result.returncode, 2, output(result))
                self.assertIn(f"{lock}: jscpd.binary: expected a safe relative path", result.stderr)
                self.assertFalse(tools.exists())

    def test_fetch_check_rejects_missing_or_malformed_lock(self) -> None:
        lock = self.base / "lock.toml"
        tools = self.base / "tools"
        for content, diagnostic in (
            (None, "expected a tool lock file, got missing"),
            (b"[jscpd\n", "expected valid TOML"),
            (b"\xff", "expected valid TOML"),
            (b"value = " + b"9" * 5000, "expected valid TOML"),
            (b'[jscpd]\nversion = "9.9.9"\n', "jscpd.url: expected"),
        ):
            with self.subTest(diagnostic=diagnostic):
                if content is not None:
                    lock.write_bytes(content)
                result = self.check_install(lock, tools)
                self.assertEqual(result.returncode, 2, output(result))
                self.assertIn(str(lock), result.stderr)
                self.assertIn(diagnostic, result.stderr)
                self.assertFalse(tools.exists())
        lock.unlink()
        lock.mkdir()
        result = self.check_install(lock, tools)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn(f"{lock}: expected a readable tool lock file", result.stderr)
        self.assertFalse(tools.exists())

    def test_fetch_check_rejects_excessive_toml_nesting(self) -> None:
        """Run parser stack exhaustion in a child to preserve the suite's tracer."""
        lock = self.base / "lock.toml"
        lock.write_bytes(b"value = " + b"[" * 2000 + b"0" + b"]" * 2000)
        tools = self.base / "tools"
        result = self.run_qg_process(
            "tools", "fetch", "--lock", str(lock), "--check", env={"QG_TOOLS_DIR": str(tools)}
        )
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn(f"{lock}: expected valid TOML", result.stderr)
        self.assertFalse(tools.exists())

    def test_fetch_check_leaves_fresh_checkout_and_cache_unchanged(self) -> None:
        checkout = self.base / "gate"
        shutil.copytree(
            GATE / "quality_gate", checkout / "quality_gate",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        shutil.copyfile(GATE / "qg.py", checkout / "qg.py")
        tools = self.base / "tools"
        directory = self.seed_check_install(tools)
        self.check_lock(directory, checkout / "tools.lock.toml")
        checkout_digest = payload_digest(checkout)
        cache_digest = payload_digest(tools)
        paths = [checkout, *checkout.rglob("*"), tools, *tools.rglob("*")]
        modes = {path: path.stat().st_mode for path in paths}
        result = subprocess.run(
            [sys.executable, "-BI", "qg.py", "tools", "fetch", "--check"],
            cwd=checkout, env=self.env({"QG_TOOLS_DIR": str(tools)}),
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(list(checkout.rglob("__pycache__")), [])
        self.assertEqual(payload_digest(checkout), checkout_digest)
        self.assertEqual(payload_digest(tools), cache_digest)
        self.assertEqual({path: path.stat().st_mode for path in paths}, modes)

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
        tools = self.fetch_refused(
            archive,
            "archive does not contain 'jscpd'; nothing installed",
        )
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

    def test_fetch_unreadable_payload_exits_2(self) -> None:
        archive = self.make_tarball()
        lock = self.write_lock(
            archive.as_uri(),
            self.sha256(archive),
            payload=self.archive_payload(archive),
        )
        tools = self.base / "tools"
        scandir = os.scandir

        def unreadable(path: object) -> object:
            if isinstance(path, (str, os.PathLike)) and Path(path).name == "build":
                raise PermissionError("Permission denied")
            return scandir(path)

        stderr = io.StringIO()
        with mock.patch(
            "quality_gate.payload.os.scandir", side_effect=unreadable
        ), mock.patch.dict(os.environ, {"QG_TOOLS_DIR": str(tools)}):
            with contextlib.redirect_stderr(stderr):
                code = main(["tools", "fetch", "--lock", str(lock)])
        text = stderr.getvalue()
        self.assertEqual(code, 2, text)
        self.assertIn("jscpd", text)
        self.assertIn("build", text)
        self.assertIn("Permission denied", text)
        self.assertNotIn("Traceback", text)
        self.assert_not_installed(tools)

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

    def test_fetch_conda_installs_payload_without_running_scripts(self) -> None:
        package = self.make_conda(self.conda_members())
        lock = self.conda_lock(package)
        tools = self.base / "tools"
        result = self.fetch(lock, tools)
        self.assertEqual(result.returncode, 0, output(result))
        directory = tools / f"jscpd-{VERSION}"
        self.assertEqual(payload_digest(directory), payload_digest(self.base / "expected"))
        for hook in CONDA_HOOKS:
            self.assertFalse((directory / hook).exists(), hook)
        self.assertFalse((self.base / "script-ran").exists())
        self.assertFalse((directory / "info").exists())
        self.assertEqual((directory / "bin/example").stat().st_mode & 0o777, 0o555)
        package.unlink()
        result = self.check_install(lock, tools)
        self.assertEqual(result.returncode, 0, output(result))

    def test_fetch_conda_uses_data_filter_for_payload(self) -> None:
        package = self.make_conda(self.conda_members())
        tool = self.conda_tool(package)
        destination = self.base / "destination"
        destination.mkdir()
        extractall = tarfile.TarFile.extractall
        calls = []

        def observe(archive, path, *, members, filter):
            calls.append((path, [member.name for member in members], filter))
            return extractall(archive, path, members=members, filter=filter)

        with mock.patch.object(tarfile.TarFile, "extractall", observe):
            gate_tools._extract_archive(package, destination, tool)
        self.assertEqual(calls, [(destination, ["bin/example", "share/data"], "data")])
        self.assertEqual(payload_digest(destination), tool.payload_sha256)

    def test_fetch_conda_accepts_matching_stems_with_leading_underscore(self) -> None:
        members = {
            name.replace("-example", "-_example"): content
            for name, content in self.conda_members().items()
        }
        package = self.make_conda(members)
        tools = self.base / "tools"
        result = self.fetch(self.conda_lock(package), tools)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertTrue((tools / f"jscpd-{VERSION}" / "bin/example").is_file())

    def test_fetch_conda_rejects_invalid_container(self) -> None:
        members = self.conda_members()
        info = "info-example-1-0.tar.zst"
        payload = "pkg-example-1-0.tar.zst"
        layout_error = "expected exactly metadata.json and matching info- and pkg-*.tar.zst members"
        for name, replacement in (
            (info, "info-other-1-0.tar.zst"),
            (info, "../" + info),
            (payload, "payload.tar.zst"),
            ("metadata.json", "other.json"),
        ):
            with self.subTest(name=name, replacement=replacement):
                entries = members.copy()
                entries[replacement] = entries.pop(name)
                self.assert_conda_refused(self.make_conda(entries), layout_error)

        for name in members:
            with self.subTest(missing=name):
                entries = members.copy()
                del entries[name]
                self.assert_conda_refused(self.make_conda(entries), layout_error)

        self.assert_conda_refused(self.make_conda(members, "extra.txt"), layout_error)
        with self.assertWarnsRegex(UserWarning, "Duplicate name"):
            package = self.make_conda(members, payload)
        self.assert_conda_refused(package, layout_error)

        for name, content, diagnostic in (
            ("metadata.json", b"[]", "expected conda_pkg_format_version 2"),
            ("metadata.json", b"{}", "expected conda_pkg_format_version 2"),
            ("metadata.json", b'{"conda_pkg_format_version": 1}', "expected conda_pkg_format_version 2"),
            ("metadata.json", b'{"conda_pkg_format_version": true}', "expected conda_pkg_format_version 2"),
            ("metadata.json", b'{"conda_pkg_format_version": 2.0}',
             "expected conda_pkg_format_version 2"),
            ("metadata.json", b"{", "Expecting property name"),
            (info, b"not zstd", "Unknown frame descriptor"),
            (payload, members[payload][:-1], "incomplete Zstandard frame"),
            (info, self.conda_compress(b"not a tar archive"), "truncated header"),
            (payload, self.conda_compress(b"not a tar archive"), "truncated header"),
        ):
            with self.subTest(name=name, diagnostic=diagnostic):
                package = self.make_conda({**members, name: content})
                self.assert_conda_refused(package, f"{name}: {diagnostic}")
        package.write_bytes(b"not zip")
        self.assert_conda_refused(package, "File is not a zip file")

    def test_fetch_conda_rejects_invalid_zip_members(self) -> None:
        members = self.conda_members()
        marker = "metadata.json"
        for file_type in (stat.S_IFLNK, stat.S_IFDIR, stat.S_IFIFO):
            with self.subTest(file_type=file_type):
                entry = zipfile.ZipInfo(marker)
                entry.create_system = 3
                entry.external_attr = (file_type | 0o755) << 16
                entries = {name: content for name, content in members.items() if name != marker}
                self.assert_conda_refused(self.make_conda(entries, entry), "is not a regular file")

        entries = members.copy()
        entries["metadata.json_hidden"] = entries.pop(marker)
        package = self.make_conda(entries)
        package.write_bytes(package.read_bytes().replace(b"metadata.json_hidden", b"metadata.json\0hidden"))
        self.assert_conda_refused(package, "invalid ZIP member name")

        package = self.make_conda(members)
        content = members["info-example-1-0.tar.zst"]
        damaged = bytes([content[0] ^ 1]) + content[1:]
        package.write_bytes(package.read_bytes().replace(content, damaged, 1))
        self.assert_conda_refused(package, "info-example-1-0.tar.zst: Bad CRC-32")

    def test_fetch_conda_names_unexpected_and_duplicate_zip_members(self) -> None:
        members = self.conda_members()
        with self.assertWarnsRegex(UserWarning, "Duplicate name"):
            duplicate = self.make_conda(members, "metadata.json")
        self.assert_conda_refused(duplicate, "duplicate ZIP member 'metadata.json'")
        self.assert_conda_refused(
            self.make_conda(members, "unrecognized"), "unexpected ZIP member 'unrecognized'"
        )
        self.assert_conda_refused(
            self.make_conda(members, "extra/"), "ZIP member 'extra/' is not a regular file"
        )

    def test_fetch_conda_rejects_dos_directory_and_volume_label_members(self) -> None:
        members = self.conda_members()
        name = "metadata.json"
        metadata = members.pop(name)
        for attribute in (0x10, 0x08):
            with self.subTest(attribute=attribute):
                entry = zipfile.ZipInfo(name)
                entry.create_system = 0
                entry.external_attr = attribute
                package = self.make_conda({})
                with zipfile.ZipFile(package, "w") as archive:
                    archive.writestr(entry, metadata)
                    for member, content in members.items():
                        archive.writestr(member, content)
                self.assert_conda_refused(package, f"ZIP member {name!r} is not a regular file")

    def test_fetch_conda_accepts_zip64_with_data_descriptors(self) -> None:
        class Unseekable(io.BytesIO):
            def seek(self, *args: int) -> int:
                raise OSError("stream is not seekable")

        members = self.conda_members()
        stream = Unseekable()
        with mock.patch.object(zipfile, "ZIP64_LIMIT", 16), zipfile.ZipFile(stream, "w") as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        package = self.base / "streamed.conda"
        raw = stream.getvalue()
        package.write_bytes(raw)
        tools = self.base / "tools"
        result = self.fetch(self.conda_lock(package), tools)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(
            payload_digest(tools / f"jscpd-{VERSION}"), payload_digest(self.base / "expected")
        )

    def test_fetch_conda_rejects_duplicate_metadata_keys_and_non_json_constants(self) -> None:
        members = self.conda_members()
        for metadata, diagnostic in (
            (b'{"conda_pkg_format_version": 1, "conda_pkg_format_version": 2}',
             "unique JSON object names, got duplicate name 'conda_pkg_format_version'"),
            (b'{"conda_pkg_format_version": 2, "nested": {"key": 1, "key": 1}}',
             "unique JSON object names, got duplicate name 'key'"),
            (b'{"conda_pkg_format_version": 2, "number": NaN}',
             "a JSON value, got non-JSON constant 'NaN'"),
            (b'{"conda_pkg_format_version": 2, "number": Infinity}',
             "a JSON value, got non-JSON constant 'Infinity'"),
            (b'{"conda_pkg_format_version": 2, "number": -Infinity}',
             "a JSON value, got non-JSON constant '-Infinity'"),
        ):
            with self.subTest(diagnostic=diagnostic):
                package = self.make_conda({**members, "metadata.json": metadata})
                self.assert_conda_refused(package, f"metadata.json: expected {diagnostic}")

    def test_fetch_conda_rejects_unsafe_members(self) -> None:
        members = self.conda_members()
        for name in ("../escape", str(self.base / "escape")):
            with self.subTest(name=name):
                members["pkg-example-1-0.tar.zst"] = self.conda_tar({
                    "bin/example": (b"fake", 0o755),
                    name: (b"outside", 0o644),
                })
                self.assert_conda_refused(
                    self.make_conda(members), f"unsafe archive member {name!r}",
                )
                self.assertFalse((self.base / "escape").exists())

        for member_type, diagnostic in (
            (tarfile.SYMTYPE, "is a link"),
            (tarfile.LNKTYPE, "is a link"),
            (tarfile.CHRTYPE, "is not a regular file"),
            (tarfile.FIFOTYPE, "is not a regular file"),
        ):
            with self.subTest(member_type=member_type):
                member = tarfile.TarInfo("unsafe")
                member.type = member_type
                member.linkname = "bin/example"
                members["pkg-example-1-0.tar.zst"] = self.conda_tar(
                    {"bin/example": (b"fake", 0o755)}, extra=member
                )
                self.assert_conda_refused(
                    self.make_conda(members), f"unsafe archive member 'unsafe' {diagnostic}"
                )

    def test_extract_conda_checks_all_members_before_writing(self) -> None:
        members = self.conda_members()
        members["pkg-example-1-0.tar.zst"] = self.conda_tar({
            "bin/example": (b"fake", 0o755),
            "../conda-escape": (b"outside", 0o644),
        })
        archive = self.make_conda(members)
        destination = self.base / "destination"
        destination.mkdir()
        tool = self.conda_tool(archive)
        with self.assertRaisesRegex(GateError, "pkg-example-1-0.tar.zst: .*unsafe archive member"):
            gate_tools._extract_archive(archive, destination, tool)
        self.assertEqual(list(destination.iterdir()), [])
        self.assertFalse((self.base / "conda-escape").exists())

    def assert_conda_tar_refused_before_write(
        self, members: dict[str, bytes], raw: bytes, diagnostic: str,
    ) -> None:
        destination = self.base / "conda-destination"
        destination.mkdir(exist_ok=True)
        for tarball in ("info-example-1-0.tar.zst", "pkg-example-1-0.tar.zst"):
            with self.subTest(tarball=tarball, diagnostic=diagnostic):
                archive = self.make_conda({**members, tarball: self.conda_compress(raw)})
                with self.assertRaises(GateError) as raised:
                    gate_tools._extract_archive(archive, destination, self.conda_tool(archive))
                self.assertIn(tarball, str(raised.exception))
                self.assertIn(diagnostic, str(raised.exception))
                self.assertEqual(list(destination.iterdir()), [])

    def test_extract_conda_rejects_unsafe_tar_entries_before_writing(self) -> None:
        members = self.conda_members()
        regular = (b"fake", 0o755)
        files = {"bin/example": regular}
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "bin/example"
        root = tarfile.TarInfo("/")
        root.type = tarfile.DIRTYPE
        for raw, diagnostic in (
            (self.raw_tar({**files, "bin/./example": regular}), "duplicate normalized tar path bin/example"),
            (self.raw_tar({**files, "bin": regular}), "has regular file bin as a parent"),
            (self.raw_tar({"bin": regular, **files}), "has regular file bin as a parent"),
            (self.raw_tar({**files, "../escape": regular}), "unsafe archive member '../escape'"),
            (self.raw_tar(files, link), "unsafe archive member 'link' is a link"),
            (self.raw_tar(files, root), "unsafe archive member"),
        ):
            self.assert_conda_tar_refused_before_write(members, raw, diagnostic)

    def test_extract_conda_rejects_pax_path_with_nul_before_writing(self) -> None:
        member = tarfile.TarInfo("extra")
        member.pax_headers = {"path": "extra\0hidden", "GNU.sparse.name": "extra"}
        raw = self.raw_tar({"bin/example": (b"fake", 0o755)}, member)
        self.assert_conda_tar_refused_before_write(
            self.conda_members(), raw, "unsafe archive member 'extra\\x00hidden'"
        )

    def test_fetch_conda_reports_decoder_failure(self) -> None:
        package = self.make_conda(self.conda_members())
        with mock.patch(
            "ctypes.CDLL", side_effect=OSError("libzstd.so.1 unavailable"),
        ):
            self.assert_conda_refused(package, "libzstd.so.1 unavailable")
        library = ctypes.CDLL("libzstd.so.1")
        with mock.patch("ctypes.CDLL", return_value=library), mock.patch.object(
            library, "ZSTD_createDStream", return_value=None
        ):
            self.assert_conda_refused(package, "cannot allocate a Zstandard decoder")

    def test_fetch_conda_rejects_missing_binary(self) -> None:
        members = self.conda_members()
        members["pkg-example-1-0.tar.zst"] = self.conda_tar({"share/data": (b"data", 0o644)})
        self.assert_conda_refused(self.make_conda(members), "archive does not contain 'bin/example'")

    def test_fetch_conda_rejects_wrong_archive_digest(self) -> None:
        package = self.make_conda(self.conda_members())
        expected = "0" * 64
        with (
            mock.patch.object(zipfile, "ZipFile") as read_zip,
            mock.patch.object(tarfile, "open") as read_tar,
        ):
            self.assert_conda_refused(
                package, f"sha256 mismatch for {package.as_uri()}: "
                f"expected {expected}, got {self.sha256(package)}",
                digest=expected,
            )
        read_zip.assert_not_called()
        read_tar.assert_not_called()

    def test_fetch_conda_rejects_wrong_payload_digest(self) -> None:
        package = self.make_conda(self.conda_members())
        self.assert_conda_refused(
            package, "payload sha256 mismatch", payload="0" * 64,
        )

    def conda_tool(
        self, package: Path, *, digest: str | None = None, payload: str | None = None,
    ) -> Tool:
        return Tool(
            "jscpd", VERSION, package.as_uri(), digest or self.sha256(package),
            payload or payload_digest(self.base / "expected"), "bin/example", "conda",
        )

    def assert_conda_refused(
        self, package: Path, diagnostic: str, **overrides: str
    ) -> None:
        tool = self.conda_tool(package, **overrides)
        tools = self.base / "tools"
        tools.mkdir(exist_ok=True)
        with self.assertRaises(GateError) as raised:
            gate_tools._fetch_tool(tool, tools)
        error = raised.exception
        self.assertEqual(error.exit_code, 1, str(error))
        self.assertIn(f"jscpd {VERSION}", str(error))
        self.assertIn(diagnostic, str(error))
        self.assertEqual(list(tools.iterdir()), [])

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
        self.fetch_wheel_refused(
            wheel,
            "unsafe archive member '../escape'; nothing installed",
        )
        self.assertFalse((self.base / "escape").exists())

    def test_fetch_wheel_refuses_absolute_member(self) -> None:
        outside = self.base / "wheel-absolute"
        wheel = self.make_wheel(
            files={
                str(outside): b"evil\n",
                "pkg/__init__.py": b"VALUE = 1\n",
            }
        )
        self.fetch_wheel_refused(
            wheel,
            f"unsafe archive member {str(outside)!r}; nothing installed",
        )
        self.assertFalse(outside.exists())

    def test_fetch_wheel_refuses_symlink_member(self) -> None:
        outside = self.base / "wheel-link"
        wheel = self.make_wheel(
            files={"pkg/__init__.py": b"VALUE = 1\n"},
            links={"pkg/link": str(outside)},
        )
        self.fetch_wheel_refused(
            wheel,
            "unsafe archive member 'pkg/link' is a link; "
            "nothing installed",
        )
        self.assertFalse(outside.exists())

    def test_fetch_wheel_refuses_device_member(self) -> None:
        wheel = self.make_wheel(
            files={
                "pkg/__init__.py": b"VALUE = 1\n",
                "pkg/device": b"",
            },
            modes={"pkg/device": stat.S_IFCHR | 0o644},
        )
        self.fetch_wheel_refused(
            wheel,
            "unsafe archive member 'pkg/device' is not a regular file; "
            "nothing installed",
        )

    def test_wheel_member_path_reads_the_shared_member_table(self) -> None:
        tool = Tool(
            name="jscpd",
            version=VERSION,
            url="file:///unused",
            sha256="0" * 64,
            payload_sha256="0" * 64,
            binary="pkg/__init__.py",
            format="wheel",
        )
        link = zipfile.ZipInfo("pkg/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(GateError) as raised:
            _wheel_member_path(link, tool)
        self.assertEqual(
            str(raised.exception),
            f"tools: jscpd {VERSION}: unsafe archive member 'pkg/link' "
            "is a link; nothing installed",
        )
        device = zipfile.ZipInfo("pkg/device")
        device.create_system = 3
        device.external_attr = (stat.S_IFCHR | 0o644) << 16
        with self.assertRaises(GateError) as raised:
            _wheel_member_path(device, tool)
        self.assertEqual(
            str(raised.exception),
            f"tools: jscpd {VERSION}: unsafe archive member 'pkg/device' "
            "is not a regular file; nothing installed",
        )
        escape = zipfile.ZipInfo("../escape")
        with self.assertRaises(GateError) as raised:
            _wheel_member_path(escape, tool)
        self.assertEqual(
            str(raised.exception),
            f"tools: jscpd {VERSION}: unsafe archive member '../escape'; "
            "nothing installed",
        )
        directory = zipfile.ZipInfo("pkg/")
        directory.create_system = 3
        directory.external_attr = (stat.S_IFDIR | 0o755) << 16
        self.assertEqual(str(_wheel_member_path(directory, tool)), "pkg")

    def test_direct_extractors_refuse_member_kinds_without_writes(self) -> None:
        tar_path = self.make_tarball(files={"../tar-escape": b"evil\n"})
        self.extract_refused(
            _extract_tar,
            tar_path,
            "unsafe archive member '../tar-escape'; nothing installed",
            self.base / "tar-escape",
        )
        tar_link = self.make_tarball(
            files={"jscpd": b"binary\n"},
            links={"tar-link": str(self.base / "tar-link")},
        )
        self.extract_refused(
            _extract_tar,
            tar_link,
            "unsafe archive member 'tar-link' is a link; "
            "nothing installed",
            self.base / "tar-link",
        )
        tar_device = self.make_tarball(
            files={"jscpd": b"binary\n"},
            devices=["tar-device"],
        )
        self.extract_refused(
            _extract_tar,
            tar_device,
            "unsafe archive member 'tar-device' is not a regular file; "
            "nothing installed",
            self.base / "tar-device",
        )
        wheel_path = self.make_wheel(files={"../wheel-escape": b"evil\n"})
        self.extract_refused(
            _extract_wheel,
            wheel_path,
            "unsafe archive member '../wheel-escape'; nothing installed",
            self.base / "wheel-escape",
        )
        wheel_link = self.make_wheel(
            files={"pkg/__init__.py": b"VALUE = 1\n"},
            links={"pkg/link": str(self.base / "wheel-link")},
        )
        self.extract_refused(
            _extract_wheel,
            wheel_link,
            "unsafe archive member 'pkg/link' is a link; "
            "nothing installed",
            self.base / "wheel-link",
        )
        wheel_device = self.make_wheel(
            files={
                "pkg/__init__.py": b"VALUE = 1\n",
                "pkg/device": b"",
            },
            modes={"pkg/device": stat.S_IFCHR | 0o644},
        )
        self.extract_refused(
            _extract_wheel,
            wheel_device,
            "unsafe archive member 'pkg/device' is not a regular file; "
            "nothing installed",
            self.base / "wheel-device",
        )

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
        self.assertIn("one of tar, wheel, conda", text)

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
            "quality_gate.payload.os.scandir", side_effect=unreadable
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
