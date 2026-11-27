from __future__ import annotations

import gzip
import hashlib
import json
import re
from dataclasses import asdict, replace
from functools import partial
from pathlib import Path
from unittest import mock

from support import BASE_CONFIG, GATE, FixtureCase

from quality_gate import adapters, public_hardware_model as model, runner, secrets, tools
from quality_gate.policy import ConfigError
from test_secrets import DECLARATION, _synthetic_credential

_LABEL = b"nvidia-h100-sxm5-80gb"
_OTHER_LABEL = _LABEL.replace(b"h100", b"h800")
_ASSIGNMENT = b'key": "' + _LABEL + b'"'
_CATALOGUE = "catalogue/models.py"
_SOURCE = b'# Public accelerator model table\nMODELS = {"' + _LABEL + b'": 80}\n'
_RULE = """
[[rule]]
pattern = "*.json*"
class = "config"
reason = "synthetic measurements"
"""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _child(rows: list[dict]) -> runner.RunResult:
    return runner.RunResult((), "completed", 3 if rows else 0, stdout=json.dumps(rows).encode())


def _row(path: str, span: tuple[int, int]) -> dict:
    return {
        "RuleID": "generic-api-key", "File": path,
        "StartLine": 1, "EndLine": 1, "StartColumn": span[0] + 1, "EndColumn": span[1],
        "Match": 'key": "REDACTED"', "Secret": "REDACTED",
        "Attributes": {"path": path, "resource": "fs.content", "confidence": "low"},
        "Tags": [], "SymlinkFile": "", "Fingerprint": f"{path}:generic-api-key:1",
        "Description": "Synthetic scanner report", "Entropy": 3.5,
        "Commit": "", "Author": "", "Email": "", "Date": "", "Message": "",
    }


def _policy_row(declaration: model.Declaration) -> dict:
    assert declaration.pointer == ("unit_key",)
    match_start, match_end = declaration.match_span
    literal_start, literal_end = declaration.catalogue.literal_span
    row = dict(
        record=declaration.record, pointer="/unit_key", match_start=match_start, match_end=match_end,
        decoded_sha256=declaration.decoded_sha256,
        catalogue=dict(payload=asdict(declaration.catalogue.payload), sha256=declaration.catalogue.sha256,
                       literal_start=literal_start, literal_end=literal_end),
    )
    if declaration.compressed_sha256 is not None:
        row["compressed_sha256"] = declaration.compressed_sha256
    return row


def _toml(value) -> str:
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{key} = {_toml(item)}" for key, item in value.items()) + " }"
    return json.dumps(value)


def _policy(*declarations: model.Declaration) -> str:
    tables = [
        "[[checks.secrets.public_hardware_model_v1]]\n"
        + "\n".join(f"{name} = {_toml(value)}" for name, value in _policy_row(declaration).items())
        for declaration in declarations
    ]
    return BASE_CONFIG + _RULE + DECLARATION + "\n".join(tables) + "\n"


class PublicHardwareModelTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        self.add_file(_CATALOGUE, _SOURCE)
        self.add_file("catalogue/other.py", _SOURCE.replace(_LABEL, _OTHER_LABEL))
        self.commit_all("public catalogue")
        commit = self.git("rev-parse", "HEAD").stdout.strip()
        blob = self.git("rev-parse", f"HEAD:{_CATALOGUE}").stdout.strip()
        start = _SOURCE.index(_LABEL)
        self.catalogue = model.Catalogue(
            secrets.GitPayload(_CATALOGUE, commit, blob, len(_SOURCE)),
            _sha(_SOURCE), (start, start + len(_LABEL)),
        )
        self.directory = self.base / "snapshot"
        self.directory.mkdir()
        self.reader = secrets._GitPayloadReader(partial(adapters._secrets_git_command, self.repo, 60))

    def _record(
        self, data: bytes = b'{"unit_key": "' + _LABEL + b'"}\n', *, archive: bool = False,
    ) -> model.Declaration:
        name = "measurement.json.gz" if archive else "measurement.json"
        start = data.index(_ASSIGNMENT)
        content = gzip.compress(data, mtime=0) if archive else data
        (self.directory / name).write_bytes(content)
        return model.Declaration(
            name, ("unit_key",), (start, start + len(_ASSIGNMENT)), _sha(data),
            self.catalogue, _sha(content) if archive else None,
        )

    def _prepare(self, *declarations: model.Declaration):
        paths = {declaration.record: True for declaration in declarations}
        return model.prepare(declarations, paths, set(paths), self.reader.read)

    def _verified(self, declaration: model.Declaration, row: dict | None = None) -> set[int]:
        finding = row if row is not None else _row(declaration.record, declaration.match_span)
        return model.verified_rows(
            [finding], self.directory, mock.Mock(return_value=_child([finding])),
            proofs=self._prepare(declaration),
        )

    def _require_scanner(self) -> Path:
        tool = tools.load_tools(GATE / "tools.lock.toml")["betterleaks"]
        if not tools._tool_binary(tool, tools._tools_dir()).exists():
            self.skipTest("pinned Betterleaks is absent")
        return tools.tool_binary("betterleaks").resolve()

    def _cli(self, expected: int, trusted: Path | None = None, *options: str):
        args = ["check", "--json", *options]
        if trusted is None:
            args.extend(("--only", "secrets"))
        else:
            args.extend(("--policy-from", str(trusted)))
        cache = self._require_scanner().parent.parent
        result = self.run_qg_process(*args, env={"QG_TOOLS_DIR": str(cache)})
        self.assertEqual(result.returncode, expected, result.stderr)
        for value in (_LABEL.decode(), _synthetic_credential()):
            self.assertNotIn(value, result.stdout + result.stderr)
        return result, self.check_by_id(self.parse_json(result), "secrets")

    def test_real_default_and_direct_scans_keep_same_line_credentials_and_other_generic_match(self) -> None:
        binary = self._require_scanner()
        fake = _synthetic_credential().encode()
        data = b'{"unit_key": "' + _LABEL + b'", "token": "' + fake + b'"}\n'
        raw = self._record(data)
        gzip_record = self._record(data, archive=True)
        undeclared = "unrelated.json"
        (self.directory / undeclared).write_bytes(b'{"unit_key": "' + _LABEL + b'"}\n')
        argv = [*secrets._scanner_argv(binary), "--exit-code=3", "--report-format=json", "--report-path=-"]

        def run_report(paths, *flags):
            return runner.run(
                [*argv, *flags, "--", *paths], cwd=self.directory, env={},
                budget_seconds=20, capture_limit=None,
            )

        paths = [raw.record, gzip_record.record, undeclared]
        rows = secrets._report(run_report(paths))
        self.assertEqual(
            sorted((row["File"], row["RuleID"], row["StartLine"]) for row in rows),
            sorted([(path, "generic-api-key", 1) for path in paths]
                   + [(path, "github-pat", 1) for path in paths[:2]]),
        )
        paths_selected = dict.fromkeys(paths, True)
        verify = model.prepare_scan((raw, gzip_record), paths_selected, set(paths), self.reader.read)
        verified = verify(rows, self.directory, run_report)
        self.assertEqual(
            {(rows[index]["File"], rows[index]["RuleID"]) for index in verified},
            {(raw.record, "generic-api-key"), (gzip_record.record, "generic-api-key")},
        )
        self.assertEqual(
            sorted(row["RuleID"] for index, row in enumerate(rows) if index not in verified),
            ["generic-api-key", "github-pat", "github-pat"],
        )

    def test_trusted_cli_keeps_the_adjacent_credential_in_raw_and_gzip(self) -> None:
        data = b'{"unit_key": "' + _LABEL + b'", "token": "' + _synthetic_credential().encode() + b'"}\n'
        declarations = (self._record(data), self._record(data, archive=True))
        for declaration in declarations:
            self.add_file(declaration.record, (self.directory / declaration.record).read_bytes())
        self.write_config(_policy(*declarations))
        self.commit_all()

        output, standalone = self._cli(1)
        self.assertNotIn("verified_public_hardware_models", standalone.get("measurement") or {})
        self.assertEqual(len(re.findall(r"(?m)^RuleID:\s+generic-api-key$", output.stderr)), 2)
        result, check = self._cli(1, self.trusted_directory("HEAD"))
        self.assertEqual(check["measurement"], {
            "verified_sha256_provenance": 0, "verified_public_hardware_models": 2,
        })
        self.assertEqual(check["reason"], "Betterleaks reported 2 unresolved finding(s)")
        self.assertEqual(result.stderr.count("RuleID: github-pat"), 2)
        self.assertNotIn("RuleID: generic-api-key", result.stderr)

    def test_authorized_candidate_policy_is_inoperative_and_obsolete_trusted_bytes_fail(self) -> None:
        declaration = self._record()
        original = (self.directory / declaration.record).read_bytes()
        self.add_file(declaration.record, original)
        self.write_config(_policy())
        self.commit_all()
        trusted_empty = self.trusted_directory("HEAD")
        self.write_config(_policy(declaration))
        result, check = self._cli(1, trusted_empty, "--allow-protected", "quality-gate.toml")
        self.assertNotIn("verified_public_hardware_models", check.get("measurement") or {})
        self.assertRegex(result.stderr, r"(?m)^RuleID:\s+generic-api-key$")

        self.commit_all()
        trusted_model = self.trusted_directory("HEAD", "trusted-model")
        _, check = self._cli(0, trusted_model)
        self.assertEqual(check["measurement"]["verified_public_hardware_models"], 1)
        self.add_file(declaration.record, original + b" ")
        result, check = self._cli(1, trusted_model)
        self.assertEqual(check["measurement"]["verified_public_hardware_models"], 0)
        self.assertIn("RuleID: generic-api-key", result.stderr)

    def test_same_value_at_another_pointer_and_other_physical_span_do_not_match(self) -> None:
        declaration = self._record(b'{"unit_key": "' + _LABEL + b'", "copy": "' + _LABEL + b'"}\n')
        self.assertEqual(self._verified(declaration), {0})
        self.assertEqual(self._verified(replace(declaration, pointer=("copy",))), set())
        start, end = declaration.match_span
        self.assertEqual(self._verified(replace(declaration, match_span=(start + 1, end))), set())

    def test_nested_array_pointer_binds_the_declared_span_once(self) -> None:
        declaration = replace(
            self._record(b'{"a/b": [{"~measurement": {"unit_' + _ASSIGNMENT + b'}}]}'),
            pointer=("a/b", "0", "~measurement", "unit_key"),
        )
        self.assertEqual(self._verified(declaration), {0})
        wrong_index = ("a/b", "00", "~measurement", "unit_key")
        self.assertEqual(self._verified(replace(declaration, pointer=wrong_index)), set())
        row = _row(declaration.record, declaration.match_span)
        replay = mock.Mock(return_value=_child([row]))
        proofs = self._prepare(declaration, declaration)
        self.assertEqual(model.verified_rows([row], self.directory, replay, proofs=proofs), set())
        replay.assert_not_called()

    def test_duplicate_json_members_and_ambiguous_same_line_templates_stay_unresolved(self) -> None:
        selected = b'"selected": {"unit_' + _ASSIGNMENT + b'}'
        other = b'"other": {"unit_' + _ASSIGNMENT.replace(_LABEL, _OTHER_LABEL) + b'}'
        for data, pointer in (
            (b'{"unit_key": "' + _LABEL + b'", "duplicate": 0, "duplicate": 1}', ("unit_key",)),
            (b"{" + selected + b", " + other + b"}", ("selected", "unit_key")),
            (b"{" + other + b", " + selected + b"}", ("selected", "unit_key")),
            (b'{"unit_key": "' + _LABEL + b'", "other": NaN}', ("unit_key",)),
        ):
            with self.subTest(pointer=pointer):
                declaration = replace(self._record(data), pointer=pointer)
                self.assertEqual(self._verified(declaration), set())

    def test_catalogue_is_exact_reachable_git_operand_with_a_complete_literal(self) -> None:
        declaration = self._record()
        broken = "catalogue/broken.py"
        broken_source = _SOURCE.removesuffix(b"}\n")
        self.add_file(broken, broken_source)
        self.commit_all("synthetic malformed catalogue")
        broken_commit = self.git("rev-parse", "HEAD").stdout.strip()
        broken_blob = self.git("rev-parse", f"HEAD:{broken}").stdout.strip()
        self.add_file(_CATALOGUE, b"The working copy is irrelevant.\n")
        self.assertEqual(model._catalogue_label(self.reader.read, self.catalogue), _LABEL.decode())
        self.assertEqual(self._verified(declaration), {0})
        operand = self.catalogue.payload
        unreachable = self.git(
            "commit-tree", f"{operand.commit}^{{tree}}", "-m", "outside HEAD",
        ).stdout.strip()
        other = "catalogue/other.py"
        other_blob = self.git("rev-parse", f"HEAD:{other}").stdout.strip()
        first, last = self.catalogue.literal_span
        invalid_catalogues = (
            replace(self.catalogue, payload=secrets.GitPayload(
                broken, broken_commit, broken_blob, len(broken_source),
            ), sha256=_sha(broken_source)),
            replace(self.catalogue, payload=replace(operand, size=operand.size + 1)),
            replace(self.catalogue, payload=replace(operand, commit=unreachable)),
            replace(self.catalogue, payload=replace(operand, path="catalogue/*.py")),
            replace(self.catalogue, payload=replace(operand, blob=other_blob)),
            replace(self.catalogue, payload=replace(operand, path=other, blob=other_blob),
                    sha256=_sha(_SOURCE.replace(_LABEL, _OTHER_LABEL))),
            replace(self.catalogue, sha256="0" * 64),
            replace(self.catalogue, literal_span=(first, last - 1)),
        )
        for catalogue in invalid_catalogues:
            with self.subTest(catalogue=catalogue):
                self.assertEqual(self._verified(replace(declaration, catalogue=catalogue)), set())

    def test_stale_record_json_and_either_gzip_pin_leave_the_finding_unresolved(self) -> None:
        raw = self._record()
        self.assertEqual(self._verified(raw), {0})
        path = self.directory / raw.record
        data = path.read_bytes()
        path.write_bytes(data + b" ")
        self.assertEqual(self._verified(raw), set())

        archived = self._record(archive=True)
        self.assertEqual(self._verified(archived), {0})
        self.assertEqual(self._verified(replace(archived, decoded_sha256="0" * 64)), set())
        path = self.directory / archived.record
        repacked = gzip.compress(data, mtime=1)
        path.write_bytes(repacked)
        self.assertEqual(self._verified(archived), set())
        doubled = repacked + gzip.compress(b"{}", mtime=0)
        path.write_bytes(doubled)
        self.assertEqual(self._verified(replace(archived, compressed_sha256=_sha(doubled))), set())

    def test_wrong_coordinates_report_scope_and_unexpected_metadata_are_unresolved(self) -> None:
        declaration = self._record()
        row = _row(declaration.record, declaration.match_span)
        for update in (
            {"StartColumn": row["StartColumn"] + 1}, {"EndColumn": row["EndColumn"] - 1}, {"EndLine": 2},
            {"Match": 'other_key": "REDACTED"'}, {"Secret": "unexpected"}, {"Fingerprint": "stale"},
            {"RuleID": "github-pat"}, {"Attributes": dict(row["Attributes"], resource="fs.decoded")},
            {"Attributes": dict(row["Attributes"], source_offset=0)},
            {"Attributes": dict(row["Attributes"], path="other.json")}, {"ComponentSets": []},
            {"Tags": ["decoded"]}, {"SymlinkFile": "link"}, {"Commit": "synthetic"},
        ):
            with self.subTest(update=update):
                self.assertEqual(self._verified(declaration, dict(row, **update)), set())

    def test_default_and_direct_require_exact_unique_rows_in_both_formats(self) -> None:
        for archive in (False, True):
            with self.subTest(archive=archive):
                declaration = self._record(archive=archive)
                row = _row(declaration.record, declaration.match_span)
                proofs = self._prepare(declaration)
                replay = mock.Mock(return_value=_child([row]))
                self.assertEqual(model.verified_rows([row], self.directory, replay, proofs=proofs), {0})
                replay.assert_called_once_with(
                    [declaration.record], f"--max-archive-depth={int(archive)}", "--max-decode-depth=0",
                )
                self.assertEqual(
                    model.verified_rows([row, row], self.directory, replay, proofs=proofs), set(),
                )
                for direct in ([], [row, row], [dict(row, Entropy=6.0)]):
                    replay.return_value = _child(direct)
                    self.assertEqual(model.verified_rows([row], self.directory, replay, proofs=proofs), set())
                replay.return_value = replace(_child([row]), stdout=b"invalid report")
                self.assertEqual(model.verified_rows([row], self.directory, replay, proofs=proofs), set())

    def test_invalid_primary_report_stops_before_model_proof_or_diagnostics(self) -> None:
        declaration = self._record()
        row = _row(declaration.record, declaration.match_span)
        report = mock.Mock(return_value=replace(_child([row]), stdout=b"invalid report"))
        verify = mock.Mock()
        with self.assertRaisesRegex(ValueError, "did not produce a valid JSON report"):
            secrets._scan_reports(self.directory, [declaration.record], {}, {}, report, verify)
        verify.assert_not_called()
        report.assert_called_once_with((declaration.record,))

    def test_model_policy_validates_types_pins_paths_and_unique_intervals(self) -> None:
        raw = self._record()
        row = _policy_row(raw)
        packed = _policy_row(self._record(archive=True))
        catalogue = row["catalogue"]
        payload = catalogue["payload"]
        invalid_rows = (
            (), [{}], [False], [dict(row, record="model.py")], [dict(row, record="../model.json")],
            [dict(row, pointer="/wrong~2pointer")], [dict(row, match_start=True)],
            [dict(row, match_end=row["match_start"])], [dict(row, match_end=(16 << 20) + 1)],
            [dict(row, decoded_sha256="x" * 64)], [dict(row, compressed_sha256="1" * 64)],
            [{name: value for name, value in packed.items() if name != "compressed_sha256"}],
            [dict(row, catalogue=dict(catalogue, literal_end=payload["size"] + 1))],
            [dict(row, catalogue=dict(catalogue, payload=dict(payload, path=row["record"])))],
            [dict(row, catalogue=dict(catalogue, payload=dict(payload, path="catalogue/*.py")))],
            [row, dict(row, match_end=row["match_end"] + 1)], [row, dict(row, pointer="/other")],
        )
        key = "public_hardware_model_v1"
        parsed = adapters._secrets_spec({key: [row]}, self.repo, self.config_path, "secrets")
        self.assertEqual(parsed.spec.models, (raw,))
        for declarations in invalid_rows:
            with self.subTest(declarations=declarations), self.assertRaises(ConfigError):
                adapters._public_models({key: declarations}, self.config_path, "secrets")

    def test_only_selected_tracked_records_can_get_a_proof(self) -> None:
        declaration = self._record()
        name = declaration.record
        reader = mock.Mock()
        for paths, tracked in (({}, {name}), ({name: True}, set()), ({name: False}, {name})):
            self.assertEqual(model.prepare((declaration,), paths, tracked, reader), {})
        for invalid in (replace(declaration, record="measurement.py"),
                        replace(declaration, compressed_sha256="0" * 64),
                        replace(declaration, catalogue=replace(self.catalogue, payload=replace(
                            self.catalogue.payload, path=name,
                        )))):
            self.assertEqual(model.prepare((invalid,), {invalid.record: True}, {invalid.record}, reader), {})
        reader.assert_not_called()
