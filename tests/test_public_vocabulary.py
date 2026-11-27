from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from support import BASE_CONFIG, GATE, FixtureCase
from test_secrets import DECLARATION, _synthetic_credential

from quality_gate import adapters, public_vocab, runner, secrets, tools
from quality_gate.policy import ConfigError

_REVISION = "1" * 40
_RELEASE = f"https://example.invalid/releases/{_REVISION}/tokenizer.json"
_KEYS = ("/model/vocab/password", "/model/vocab/username")
_PASSWORD_ID = 284_912
_USERNAME_ID = 693_740
_VOCAB = dict(zip(("password", "username", "stone"), (_PASSWORD_ID, _USERNAME_ID, 1), strict=True))
_RULES = """
[[rule]]
pattern = "*.json*"
class = "config"
reason = "synthetic tokenizer fixtures"
"""


def _tokenizer(vocab: dict = _VOCAB, **extra) -> bytes:
    data = {"model": {"type": "BPE", "vocab": vocab}, **extra}
    return (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _pins(path: str, raw: bytes, compressed: bytes | None = None) -> dict:
    fields = {
        "path": path,
        "published_url": _RELEASE,
        "published_revision": _REVISION,
        "published_sha256": hashlib.sha256(raw).hexdigest(),
        "published_size": len(raw),
        "pointers": list(_KEYS),
    }
    if compressed is not None:
        fields.update(
            compressed_sha256=hashlib.sha256(compressed).hexdigest(), compressed_size=len(compressed),
        )
    return fields


def _policy(*pins: dict) -> str:
    declarations = [
        "[[checks.secrets.public_vocabulary]]\n"
        + "\n".join(f"{name} = {json.dumps(value, ensure_ascii=False)}" for name, value in row.items())
        for row in pins
    ]
    return BASE_CONFIG + _RULES + DECLARATION + "\n".join(declarations) + "\n"


def _row(path: str, **extra) -> dict:
    return {
        "RuleID": "generic-password",
        "Description": "synthetic report",
        "StartLine": 5,
        "EndLine": 5,
        "StartColumn": 8,
        "EndColumn": 25,
        "Match": "password\": REDACTED,",
        "Secret": "REDACTED",
        "Attributes": {"path": path, "resource": "fs.content", "confidence": "low"},
        "Tags": [],
        "Fingerprint": f"{path}:generic-password:5",
        "File": path,
        "SymlinkFile": "",
        "Commit": "",
        "Entropy": 2.251629,
        "Author": "",
        "Email": "",
        "Date": "",
        "Message": "",
        **extra,
    }


class PublicVocabularyTests(FixtureCase):
    def _run(self, expected: int, trusted: Path | None = None, *options: str):
        pin = tools.load_tools(GATE / "tools.lock.toml")["betterleaks"]
        if not tools._tool_binary(pin, tools._tools_dir()).exists():
            self.skipTest("pinned Betterleaks is absent; run python3 -I qg.py tools fetch")
        binary = tools.tool_binary("betterleaks").resolve()
        trust = ["--only", "secrets"] if trusted is None else ["--policy-from", str(trusted)]
        result = self.run_qg_process(
            "check", "--json", *trust, *options, env={"QG_TOOLS_DIR": str(binary.parent.parent)},
        )
        self.assertEqual(result.returncode, expected, result.stderr)
        for value in ("284912", "693740", _synthetic_credential()):
            self.assertNotIn(value, result.stdout + result.stderr)
        return result, self.check_by_id(self.parse_json(result), "secrets")

    def test_trusted_raw_and_gzip_preserve_the_full_scanner_and_bind_components(self) -> None:
        raw = _tokenizer()
        packed = gzip.compress(raw, mtime=0)
        self.add_file("raw.json", raw)
        self.add_file("packed.json.gz", packed)
        self.write_config(_policy(_pins("raw.json", raw), _pins("packed.json.gz", raw, packed)))
        self.commit_all()
        trusted = self.trusted_directory("HEAD")

        outside, _ = self._run(1)
        self.assertIn("path: packed.json.gz", outside.stderr)
        self.assertIn("path: raw.json", outside.stderr)
        _, check = self._run(0, trusted)
        self.assertEqual(check["measurement"]["verified_public_vocabulary"], 2)
        self.assertEqual(check["measurement"]["verified_sha256_provenance"], 0)
        locations = check["measurement"]["public_vocabulary_locations"]
        self.assertEqual([row[0]["path"] for row in locations], ["packed.json.gz", "raw.json"])
        for primary, component in locations:
            self.assertEqual((primary["rule"], primary["start_line"]), ("generic-password", 5))
            self.assertEqual((component["rule"], component["start_line"]), ("generic-username", 6))

        self.add_file("extra.md", f'token = "{_synthetic_credential()}"\n')
        result, check = self._run(1, trusted)
        self.assertEqual(check["measurement"]["verified_public_vocabulary"], 2)
        self.assertIn("RuleID: github-pat", result.stderr)

    def test_unauthorized_or_incomplete_pointer_proof_leaves_finding(self) -> None:
        raw = _tokenizer()
        path = "raw.json"
        self.add_file(path, raw)
        self.write_config(_policy())
        self.commit_all()
        trusted = self.trusted_directory("HEAD")
        pins = _pins(path, raw)
        self.write_config(_policy(pins))
        _, check = self._run(1, trusted, "--allow-protected", "quality-gate.toml")
        self.assertNotIn("verified_public_vocabulary", check.get("measurement") or {})

        pins["pointers"] = [_KEYS[0]]
        self.write_config(_policy(pins))
        self.commit_all()
        incomplete = self.trusted_directory("HEAD", name="incomplete")
        result, check = self._run(1, incomplete)
        self.assertEqual(check["measurement"]["verified_public_vocabulary"], 0)
        self.assertIn("RuleID: generic-password", result.stderr)

    def test_equal_integer_on_another_pointer_and_string_findings_remain(self) -> None:
        raw = _tokenizer(
            account={"password": _VOCAB["password"], "username": _VOCAB["username"], "other": 1},
            secondary={"password": str(_VOCAB["password"]), "username": "fixture-user", "other": 1},
        )
        self.add_file("raw.json", raw)
        self.write_config(_policy(_pins("raw.json", raw)))
        self.commit_all()
        result, check = self._run(1, self.trusted_directory("HEAD"))
        self.assertEqual(check["measurement"]["verified_public_vocabulary"], 1)
        self.assertEqual(result.stderr.count("RuleID: generic-password"), 2)

    def test_untracked_asset_or_changed_pinned_archive_remains_unresolved(self) -> None:
        path = "packed.json.gz"
        raw = _tokenizer()
        packed = gzip.compress(raw, mtime=0)
        self.write_config(_policy(_pins(path, raw, packed)))
        self.commit_all()
        trusted = self.trusted_directory("HEAD")
        self.add_file(path, packed)
        _, check = self._run(1, trusted)
        self.assertEqual(check["measurement"]["verified_public_vocabulary"], 0)

        self.commit_all()
        self.add_file(path, gzip.compress(raw, mtime=1))
        _, check = self._run(1, trusted)
        self.assertEqual(check["measurement"]["verified_public_vocabulary"], 0)

    def test_raw_replay_is_unique_and_must_match_the_entire_row(self) -> None:
        raw = _tokenizer()
        packed = gzip.compress(raw, mtime=0)
        path = "packed.json.gz"
        component = {
            "RuleID": "generic-username", "Optional": True, "StartLine": 6, "EndLine": 6,
            "StartColumn": 7, "EndColumn": 25, "Match": "\"username\": REDACTED,", "Secret": "REDACTED",
        }
        attachments = {"ComponentSets": [{"components": [component]}]}
        normal = _row(path, **attachments)
        self.add_file(path, packed)
        proof = adapters._public_vocab_spec(_pins(path, raw, packed), self.config_path, "secrets")
        expected_raw = _row("packed.json", **attachments)

        def report(rows, execution="completed"):
            return SimpleNamespace(
                execution=execution, returncode=3 if rows else 0, output_truncated=False,
                stdout=json.dumps(rows).encode(),
            )

        for raw_report, verified in (
            (report([expected_raw, expected_raw]), False),
            (report([dict(expected_raw, Description="changed")]), False),
            (report([_row("packed.json")]), False),
            (report([], execution="timeout"), False),
            (report([expected_raw]), True),
        ):
            with self.subTest(replay=raw_report.execution, report_bytes=len(raw_report.stdout)):
                def replay(paths, *flags, cwd=None, inflated_report=raw_report):
                    self.assertIn("--max-decode-depth=0", flags)
                    if cwd is None:
                        self.assertEqual(paths, [path])
                        self.assertIn("--max-archive-depth=1", flags)
                        return report([normal])
                    self.assertEqual(paths, ["packed.json"])
                    self.assertIn("--max-archive-depth=0", flags)
                    self.assertEqual((cwd / paths[0]).read_bytes(), raw)
                    return inflated_report

                rows = secrets._verified_vocabulary_rows(self.repo, [normal], {path: proof}, replay)
                self.assertEqual(bool(rows), verified)

    def test_unknown_or_required_components_keep_the_finding(self) -> None:
        self.assertEqual(secrets._vocabulary_components(_row("raw.json")), ())
        component = {
            "RuleID": "generic-username", "Optional": True, "StartLine": 6, "EndLine": 6,
            "StartColumn": 7, "EndColumn": 25, "Match": "\"username\": REDACTED,", "Secret": "REDACTED",
        }
        for parts in (
            [],
            [{"components": [], "extra": []}],
            [{"components": [component, component]}],
            [{"components": [dict(component, Optional=1)]}],
            [{"components": [dict(component, RuleID="another-rule")]}],
        ):
            with self.subTest(components=parts):
                self.assertIsNone(secrets._vocabulary_components(_row("raw.json", ComponentSets=parts)))

    def test_report_coordinates_must_be_integer_and_on_one_existing_line(self) -> None:
        line = b'  "password": 284912,'
        row = _row(
            "raw.json", StartLine=1, EndLine=1, StartColumn=line.index(b"password") + 1, EndColumn=len(line),
        )
        keys = frozenset({"password"})
        self.assertIsNotNone(public_vocab.member_span(line, (0,), row, keys))
        for change in ({"EndLine": 2}, {"StartLine": 2, "EndLine": 2}, {"StartColumn": True}):
            with self.subTest(change=change):
                self.assertIsNone(public_vocab.member_span(line, (0,), dict(row, **change), keys))

    def test_incomplete_primary_scan_produces_no_proof_or_output(self) -> None:
        def report(targets, *flags):
            self.assertEqual(targets, ("raw.json",))
            self.assertEqual(flags, ())
            return runner.RunResult((), "budget", None, stdout=b"[", stderr=b"partial", timed_out=True)

        result = secrets._scan_reports(self.repo, ["raw.json"], {}, {}, report)
        self.assertEqual((result.unresolved, result.verified, result.vocabulary), (0, 0, ()))
        self.assertEqual(
            (result.child.execution, result.child.stdout, result.child.stderr), ("budget", b"", b""),
        )

    def test_strict_json_and_exact_byte_spans(self) -> None:
        prefix = b"{\"model\": {\"type\": \"BPE\", \"vocab\": {\n"
        line = f'  "Ωpassword": {_PASSWORD_ID},'.encode()
        start = line.index(b"password")
        row = _row("raw.json", StartLine=2, EndLine=2, StartColumn=start + 1, EndColumn=len(line))
        starts = (0, len(prefix))
        span = public_vocab.member_span(prefix + line, starts, row, frozenset({"Ωpassword"}))
        self.assertIsNotNone(span)
        self.assertEqual(public_vocab.member_span(
            prefix + line, starts, dict(row, StartColumn=start), frozenset({"Ωpassword"}),
        ), None)
        for value in (b'"284912"', b"-284912", b"0284912", b"284912.0", b"284912e0", b"true"):
            candidate = line.replace(b"284912", value)
            self.assertIsNone(public_vocab.member_span(
                prefix + candidate, starts, dict(row, EndColumn=len(candidate)), frozenset({"Ωpassword"}),
            ))
        for tail, expected in (
            (b'\n"other": 1}}}', {span}),
            (b'\n"other": 1,"other": 2}}}', set()),
            (b'\n"other": "1"}}}', set()),
            (b'\n"other": 1}},"tail":NaN}', set()),
            (b'\n"other": 1}}}extra', set()),
        ):
            with self.subTest(tail=tail):
                self.assertEqual(public_vocab.proven_spans(prefix + line + tail, {span}), expected)

    def test_member_requires_a_valid_redaction_starting_inside_its_key(self) -> None:
        line = b'  "password": 284912,'
        start = line.index(b"password") + 1
        row = _row("raw.json", StartLine=1, EndLine=1, StartColumn=start, EndColumn=len(line))
        keys = frozenset({"password"})
        self.assertIsNotNone(public_vocab.member_span(line, (0,), row, keys))
        for change in (
            {"Match": None},
            {"Secret": "masked in another format"},
            {"Match": "password\": REDACTED,REDACTED,"},
            {"Match": "REDACTED,"},
            {"Match": "\ufffdpassword\": REDACTED,"},
            {"Match": "\ud800password\": REDACTED,"},
            {"Match": ": REDACTED,", "StartColumn": line.index(b":") + 1},
        ):
            with self.subTest(change=change):
                self.assertIsNone(public_vocab.member_span(line, (0,), dict(row, **change), keys))

        misplaced = b' ' * (16 << 10) + line
        self.assertIsNone(public_vocab.member_span(
            misplaced, (0,), dict(row, StartColumn=start + (16 << 10), EndColumn=len(misplaced)), keys,
        ))
        invalid = line.replace(b'"password', b'"\xffpassword')
        self.assertIsNone(public_vocab.member_span(
            invalid, (0,), dict(row, StartColumn=start + 1, EndColumn=len(invalid)), keys,
        ))

    def test_vocabulary_limit_does_not_raise_existing_gzip_record_limit(self) -> None:
        raw = _tokenizer(padding="x" * ((16 << 20) + 1))
        path = "packed.json.gz"
        packed = gzip.compress(raw, mtime=0)
        archive = self.add_file(path, packed)
        proof = adapters._public_vocab_spec(_pins(path, raw, packed), self.config_path, "secrets")
        self.assertEqual(secrets._published_bytes(self.repo, proof), raw)
        self.assertIsNone(secrets._read_gzip_record(archive))

        single = _tokenizer()
        joined = gzip.compress(single, mtime=0) * 2
        archive.write_bytes(joined)
        proof = adapters._public_vocab_spec(_pins(path, single * 2, joined), self.config_path, "secrets")
        self.assertIsNone(secrets._published_bytes(self.repo, proof))

    def test_policy_rejects_unbounded_or_unscoped_declarations(self) -> None:
        raw = _tokenizer()
        proof = _pins("raw.json", raw)
        for overrides in (
            {"path": "../raw.json"},
            {"published_revision": "short-revision"},
            {"published_url": "https://example.invalid/releases/main/tokenizer.json"},
            {"published_size": public_vocab.MAX_PUBLISHED_BYTES + 1},
            {"published_sha256": "nope"},
            {"pointers": ["/model/vocab"]},
            {"pointers": ["/other/password"]},
            {"pointers": [_KEYS[0], _KEYS[0]]},
            {"pointers": ["/model/vocab/invalid~2escape"]},
            {"compressed_size": 1},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(ConfigError):
                adapters._public_vocab_spec(dict(proof, **overrides), self.config_path, "secrets")
        escaped = dict(proof, pointers=["/model/vocab/sample~1literal~0key"])
        parsed = adapters._public_vocab_spec(escaped, self.config_path, "secrets")
        self.assertEqual(parsed.keys, frozenset({"sample/literal~key"}))
