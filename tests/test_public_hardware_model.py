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
_PYTHON_CATALOGUE = "catalogue/synthetic.py"
_PYTHON_SOURCE = b'# Invented public accelerator catalogue for tests\nMODELS = {"quanta-x780-vm6-92gb": 92}\n'
_PYTHON_LABEL = b"quanta-x780-vm6-92gb"
_KEYWORD_MATCH = b"key='" + _PYTHON_LABEL + b"'"
_EQUALITY_MATCH = b'key == "' + _PYTHON_LABEL + b'"'
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


def _policy_row(declaration: model.ModelDeclaration) -> dict:
    match_start, match_end = declaration.match_span
    literal_start, literal_end = declaration.catalogue.literal_span
    row = dict(
        record=declaration.record, match_start=match_start, match_end=match_end,
        catalogue=dict(payload=asdict(declaration.catalogue.payload), sha256=declaration.catalogue.sha256,
                       literal_start=literal_start, literal_end=literal_end),
    )
    if isinstance(declaration, model.PythonDeclaration):
        return dict(
            row, role=declaration.role, identifier=declaration.identifier,
            source_sha256=declaration.source_sha256,
        )
    assert declaration.pointer == ("unit_key",)
    row.update(pointer="/unit_key", decoded_sha256=declaration.decoded_sha256)
    if declaration.compressed_sha256 is not None:
        row["compressed_sha256"] = declaration.compressed_sha256
    return row


def _toml(value) -> str:
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{key} = {_toml(item)}" for key, item in value.items()) + " }"
    return json.dumps(value)


def _policy(*declarations: model.ModelDeclaration) -> str:
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
        self.add_file(_PYTHON_CATALOGUE, _PYTHON_SOURCE)
        self.commit_all("public catalogue")
        self.catalogue = self._catalogue(_CATALOGUE, _SOURCE, _LABEL)
        self.python_catalogue = self._catalogue(_PYTHON_CATALOGUE, _PYTHON_SOURCE, _PYTHON_LABEL)
        self.directory = self.base / "snapshot"
        self.directory.mkdir()
        self.reader = secrets._GitPayloadReader(partial(adapters._secrets_git_command, self.repo, 60))

    def _catalogue(self, path: str, source: bytes, label: bytes) -> model.Catalogue:
        commit = self.git("rev-parse", "HEAD").stdout.strip()
        blob = self.git("rev-parse", f"HEAD:{path}").stdout.strip()
        start = source.index(label)
        return model.Catalogue(
            secrets.GitPayload(path, commit, blob, len(source)),
            _sha(source), (start, start + len(label)),
        )

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

    def _prepare(self, *declarations: model.ModelDeclaration):
        paths = {declaration.record: True for declaration in declarations}
        return model.prepare(declarations, paths, set(paths), self.reader.read)

    def _verified(self, declaration: model.ModelDeclaration, row: dict | None = None) -> set[int]:
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
        for value in (_LABEL.decode(), _PYTHON_LABEL.decode(), _synthetic_credential()):
            self.assertNotIn(value, result.stdout + result.stderr)
        return result, self.check_by_id(self.parse_json(result), "secrets")

    def _python_record(
        self, source: bytes, match: bytes = _KEYWORD_MATCH, *,
        role: str = "keyword", identifier: str = "device_key",
    ) -> tuple[model.PythonDeclaration, dict]:
        name = "measurement.py"
        (self.directory / name).write_bytes(source)
        start = source.index(match)
        span = start, start + len(match)
        declaration = model.PythonDeclaration(
            name, role, identifier, span, _sha(source), self.python_catalogue,
        )
        line = source.count(b"\n", 0, start) + 1
        column = start - (source.rfind(b"\n", 0, start) + 1)
        row = dict(
            _row(name, (column, column + len(match))),
            StartLine=line, EndLine=line, Fingerprint=f"{name}:generic-api-key:{line}",
            Match=match.replace(_PYTHON_LABEL, b"REDACTED", 1).decode("ascii"),
        )
        return declaration, row

    def test_python_trusted_cli_keeps_the_adjacent_credential(self) -> None:
        credential = _synthetic_credential().encode()
        source = (
            b"# synthetic measurement\n"
            b"measure(device_" + _KEYWORD_MATCH + b", token='" + credential + b"')\n"
            b"assert record." + _EQUALITY_MATCH + b"\n"
            b"measure(other_" + _KEYWORD_MATCH + b")\n"
        )
        keyword, _ = self._python_record(source)
        attribute, _ = self._python_record(
            source, _EQUALITY_MATCH, role="attribute_equality", identifier="key",
        )
        self.add_file(keyword.record, source)
        self.add_file("control.json", b"{}\n")
        self.commit_all("tracked synthetic Python measurements")
        self.write_config(_policy(keyword, attribute))
        self.commit_all("trusted model declarations")

        standalone, _ = self._cli(1)
        self.assertEqual(len(re.findall(r"(?m)^RuleID:\s+generic-api-key$", standalone.stderr)), 3)
        result, check = self._cli(1, self.trusted_directory("HEAD"))
        self.assertEqual(check["measurement"]["verified_public_hardware_models"], 2)
        self.assertEqual(result.stderr.count("RuleID: github-pat"), 1)
        self.assertEqual(result.stderr.count("RuleID: generic-api-key"), 1)
        self.assertIn("Line: 4\n", result.stderr)

    def test_python_binds_the_exact_identifier_and_selected_ast_role(self) -> None:
        keyword, row = self._python_record(b"measure(device_" + _KEYWORD_MATCH + b")\n")
        self.assertEqual(self._verified(keyword, row), {0})
        for wrong in ("key", "other_key"):
            self.assertEqual(self._verified(replace(keyword, identifier=wrong), row), set())
        self.assertEqual(self._verified(replace(keyword, role="attribute_equality"), row), set())
        self.assertEqual(self._verified(replace(keyword, catalogue=self.catalogue), row), set())
        self.assertEqual(self._verified(replace(keyword, source_sha256="0" * 64), row), set())
        for other in ((keyword.match_span[0] + 1, keyword.match_span[1]),
                      (keyword.match_span[0], keyword.match_span[1] - 1)):
            self.assertEqual(self._verified(replace(keyword, match_span=other), row), set())

        source = b"assert tools.describe(item)." + _EQUALITY_MATCH + b"\r\n"
        attribute, finding = self._python_record(
            source, _EQUALITY_MATCH, role="attribute_equality", identifier="key",
        )
        self.assertEqual(self._verified(attribute, finding), {0})
        self.assertEqual(self._verified(replace(attribute, role="keyword"), finding), set())
        self.assertEqual(self._verified(replace(attribute, identifier="device_key"), finding), set())

    def test_python_wrong_or_ambiguous_lexical_sites_keep_findings(self) -> None:
        literal = b"'" + _PYTHON_LABEL + b"'"
        cases = (
            (b"device_" + _KEYWORD_MATCH, _KEYWORD_MATCH),
            (b"# device_" + _KEYWORD_MATCH, _KEYWORD_MATCH),
            (b'text = "device_' + _KEYWORD_MATCH + b'"', _KEYWORD_MATCH),
            (b"load(device_" + _KEYWORD_MATCH + b" + suffix)", _KEYWORD_MATCH),
            (b"load(device_" + _KEYWORD_MATCH + b" 'additional')", _KEYWORD_MATCH),
            (b"load(device_" + _KEYWORD_MATCH + b", other_" + _KEYWORD_MATCH + b")", _KEYWORD_MATCH),
            (b"load(device_" + _KEYWORD_MATCH + b",\n     device_" + _KEYWORD_MATCH + b")", _KEYWORD_MATCH),
            (b"load(device_key= " + b"\n " + literal + b")", b"key= "),
            (b"load(device_key=(" + literal + b"))", b"key=(" + literal),
            (b"load(device_key=r" + literal + b")", b"key=r" + literal),
            (b"load(device_key=f" + literal + b")", b"key=f" + literal),
            (b"load(device_key='''" + _PYTHON_LABEL + b"''')", b"key='''" + _PYTHON_LABEL + b"'"),
            (b"load(device_key='" + _PYTHON_LABEL + b"\\x21')", b"key='" + _PYTHON_LABEL + b"\\x21'"),
            ("load(device_ｋ".encode() + _KEYWORD_MATCH[1:] + b")", _KEYWORD_MATCH[1:]),
            (b"load(**{'device_key': " + literal + b"})", b"key': " + literal),
        )
        for source, fragment in cases:
            with self.subTest(source=source):
                declaration, row = self._python_record(source + b"\n", fragment)
                self.assertEqual(self._verified(declaration, row), set())
        for source in (b"assert record." + _EQUALITY_MATCH + b" == fallback",
                       b"assert record().\n" + _EQUALITY_MATCH,
                       b"assert (" + b"\n  record\n)." + _EQUALITY_MATCH,
                       b"assert " + _EQUALITY_MATCH,
                       b"# record." + _EQUALITY_MATCH):
            with self.subTest(source=source):
                declaration, row = self._python_record(
                    source + b"\n", _EQUALITY_MATCH, role="attribute_equality", identifier="key",
                )
                self.assertEqual(self._verified(declaration, row), set())

    def test_python_requires_tracked_exact_bytes_and_a_unique_identical_replay(self) -> None:
        declaration, row = self._python_record(b"measure(device_" + _KEYWORD_MATCH + b")\n")
        name = declaration.record
        self.assertEqual(model.prepare((declaration,), {name: True}, set(), self.reader.read), {})
        self.assertEqual(model.prepare((declaration,), {name: False}, {name}, self.reader.read), {})
        proofs = self._prepare(declaration)
        replay = mock.Mock(return_value=_child([row]))
        self.assertEqual(model.verified_rows([row], self.directory, replay, proofs=proofs), {0})
        replay.assert_called_once_with([name], "--max-archive-depth=0", "--max-decode-depth=0")

        self.assertEqual(model.verified_rows([row, row], self.directory, replay, proofs=proofs), set())
        for changed in ([], [row, row], [dict(row, Description="different row")]):
            replay.return_value = _child(changed)
            self.assertEqual(model.verified_rows([row], self.directory, replay, proofs=proofs), set())
        for changed in (dict(row, Match="key = 'REDACTED'"), dict(row, StartColumn=row["StartColumn"] - 1),
                        dict(row, EndColumn=row["EndColumn"] + 1), dict(row, Secret="unredacted")):
            self.assertEqual(self._verified(declaration, changed), set())
        current = self.directory / name
        current.write_bytes(current.read_bytes() + b"# exact source pin is stale\n")
        self.assertEqual(self._verified(declaration, row), set())

    def test_python_model_policy_rejects_unknown_roles_identifiers_and_fields(self) -> None:
        declaration, _ = self._python_record(b"measure(device_" + _KEYWORD_MATCH + b")\n")
        row = _policy_row(declaration)
        key = "public_hardware_model_v1"
        self.assertEqual(adapters._public_models({key: [row]}, self.config_path, "secrets"), (declaration,))
        catalogue = row["catalogue"]
        bad = (
            dict(row, role="assignment"), dict(row, identifier="device-key"),
            dict(row, identifier="dév"), dict(row, identifier="class"), dict(row, pointer="/device_key"),
            dict(row, compressed_sha256="0" * 64), dict(row, decoded_sha256=row["source_sha256"]),
            dict(row, source_sha256="x" * 64), dict(row, record="measurement.json"),
            dict(row, match_start=True), dict(row, source_sha256=catalogue["sha256"]),
            dict(row, catalogue=dict(catalogue, payload=dict(catalogue["payload"], path=row["record"]))),
        )
        for declarations in ([row, row], *([change] for change in bad)):
            with self.subTest(declarations=declarations), self.assertRaises(ConfigError):
                adapters._public_models({key: declarations}, self.config_path, "secrets")

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
