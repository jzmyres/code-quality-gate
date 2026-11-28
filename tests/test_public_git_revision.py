from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict, replace
from functools import partial
from itertools import product
from pathlib import Path
from unittest import mock

from support import BASE_CONFIG, GATE, FixtureCase
from quality_gate import adapters, public_git_revision as revision, runner, secrets, tools
from quality_gate.policy import ConfigError
from test_public_hardware_model import _toml
from test_secrets import DECLARATION, _synthetic_credential


REPOSITORY = "synthetic-owner/SyntheticModel"
REPOSITORY_URL = "https://huggingface.co/" + REPOSITORY
MATCH_PREFIX = b'tokenizer_revision": "'
POINTER = ("receipt", "tokenizer_revision")
IDENTITY = b"Synthetic Author <fixture@example.invalid> 1690000000 +0000"
LINE_BREAKS = {"LF": b"\n", "CR": b"\r", "CRLF": b"\r\n"}
FENCE_MARKERS = [b"```json", b"```"]
RULE = """
[[rule]]
pattern = "*.json"
class = "config"
reason = "synthetic evidence record"

[[rule]]
pattern = "evidence/*.body"
class = "config"
reason = "generated Git object body"
"""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _report(rows: list[dict], exit_code: int | None = None) -> runner.RunResult:
    code = (3 if rows else 0) if exit_code is None else exit_code
    return runner.RunResult((), "completed", code, stdout=json.dumps(rows).encode())


def _scanner_row(path: str, data: bytes, span: tuple[int, int]) -> dict:
    start, end = span
    line = data.count(b"\n", 0, start) + 1
    prior = data.rfind(b"\n", 0, start)
    return {
        "RuleID": "generic-api-key", "File": path,
        "StartLine": line, "EndLine": line, "StartColumn": start - prior, "EndColumn": end - prior - 1,
        "Match": MATCH_PREFIX.decode() + 'REDACTED"', "Secret": "REDACTED",
        "Attributes": {"path": path, "resource": "fs.content", "confidence": "low"},
        "Tags": [], "SymlinkFile": "", "Fingerprint": f"{path}:generic-api-key:{line}",
        "Description": "Synthetic scanner report", "Entropy": 3.5,
        "Commit": "", "Author": "", "Email": "", "Date": "", "Message": "",
    }


def _markdown_markers(data: bytes) -> list[bytes]:
    return [line for line in data.splitlines() if line.lstrip(b" \t").startswith((b"```", b"~~~", b"<"))]


def _settings(declaration: revision.Declaration) -> dict:
    publication = declaration.publication
    return dict(
        record=declaration.record, record_sha256=declaration.record_sha256,
        pointer="/" + "/".join(declaration.pointer),
        match_start=declaration.match_span[0], match_end=declaration.match_span[1],
        publication=dict(
            repository_url=REPOSITORY_URL, revision=publication.revision,
            commit=asdict(publication.commit), tree=asdict(publication.tree),
        ),
    )


def _config(*declarations: revision.Declaration) -> str:
    tables = [
        "[[checks.secrets.public_git_revision_v1]]\n"
        + "\n".join(f"{key} = {_toml(value)}" for key, value in _settings(declaration).items())
        for declaration in declarations
    ]
    return BASE_CONFIG + RULE + DECLARATION + "\n".join(tables) + "\n"


class PublicGitRevisionTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        self.directory = self.base / "snapshot"
        self.directory.mkdir()
        self.tree = (
            b"100644 tokenizer.json\0" + bytes.fromhex(self._git_oid("blob", b'{"model": {}}'))
            + b"100644 tokenizer_config.json\0" + bytes.fromhex(self._git_oid("blob", b"{}"))
        )
        self.publication = self._archive(self.tree)
        self.reader = self._reader()

    def _reader(self) -> secrets._GitPayloadReader:
        return secrets._GitPayloadReader(partial(adapters._secrets_git_command, self.repo, 60))

    def _git_oid(self, kind: str, data: bytes) -> str:
        return subprocess.check_output(
            ["git", "hash-object", "--literally", "-t", kind, "--stdin"],
            input=data, cwd=self.repo, env=self.env(),
        ).decode("ascii").strip()

    def _archive(
        self, tree: bytes, *, headers: bytes | None = None, tree_key: bytes = b"tree",
    ) -> revision.Publication:
        if headers is None:
            headers = b"author " + IDENTITY + b"\ncommitter " + IDENTITY + b"\n"
        tree_line = tree_key + b" " + self._git_oid("tree", tree).encode()
        commit = tree_line + b"\n" + headers + b"\nSynthetic release\n"
        bodies = {"evidence/commit.body": commit, "evidence/tree.body": tree}
        for path, data in bodies.items():
            self.add_file(path, data)
        self.commit_all("generated publication")
        local_commit = self.git("rev-parse", "HEAD").stdout.strip()
        objects = [
            revision.ObjectBody(
                secrets.GitPayload(
                    path, local_commit, self.git("rev-parse", f"HEAD:{path}").stdout.strip(), len(data),
                ),
                _sha(data),
            )
            for path, data in bodies.items()
        ]
        return revision.Publication(REPOSITORY, self._git_oid("commit", commit), *objects)

    def _json(self, *, beside: str = "", publication: revision.Publication | None = None) -> bytes:
        public = publication or self.publication
        return (
            f'{{\n  "receipt": {{\n    "tokenizer": "{public.repository}",\n'
            f'    "tokenizer_revision": "{public.revision}"{beside}\n  }}\n}}\n'
        ).encode()

    def _record(
        self, data: bytes | None = None, *,
        path: str = "probe.json", publication: revision.Publication | None = None,
    ) -> tuple[revision.Declaration, dict]:
        data = self._json(publication=publication) if data is None else data
        (self.directory / path).write_bytes(data)
        start = data.index(MATCH_PREFIX)
        match = (start, start + len(MATCH_PREFIX) + 41)
        declaration = revision.Declaration(path, POINTER, match, _sha(data), publication or self.publication)
        return declaration, _scanner_row(path, data, match)

    def _prepare(self, *declarations: revision.Declaration):
        paths = dict.fromkeys((item.record for item in declarations), True)
        return revision.prepare_scan(declarations, paths, set(paths), self.reader.read)

    def _assert_no_proof(self, declaration: revision.Declaration, row: dict) -> None:
        replay = mock.Mock(return_value=_report([row]))
        self.assertEqual(self._prepare(declaration)([row], self.directory, replay), set())
        replay.assert_not_called()

    def test_synthetic_json_and_fenced_json_prove_only_the_declared_occurrences(self) -> None:
        raw, first = self._record()
        markdown = b"# Synthetic probe\n\n```json\n" + self._json() + b"```\n"
        md, second = self._record(markdown, path="probe.md")
        adjacent = dict(first, RuleID="synthetic-adjacent-rule")
        rows = [first, adjacent, second]
        replay = mock.Mock(return_value=_report(rows))
        self.assertEqual(self._prepare(raw, md)(rows, self.directory, replay), {0, 2})
        replay.assert_called_once_with(
            ["probe.json", "probe.md"], "--max-archive-depth=0", "--max-decode-depth=0",
        )
        self.assertEqual(rows, [first, adjacent, second])
        no_selected = revision.prepare_scan((raw, md), {raw.record: False, md.record: True}, {raw.record},
                                            self.reader.read)
        replay.reset_mock()
        self.assertEqual(no_selected(rows, self.directory, replay), set())
        replay.assert_not_called()

    def test_record_hash_pointer_and_publication_scope_must_match(self) -> None:
        duplicate = self._json().removeprefix(b"{\n").removesuffix(b"\n}\n").replace(b'"receipt"', b'"other"')
        data = self._json().removesuffix(b"\n}\n") + b",\n" + duplicate + b"\n}\n"
        declaration, row = self._record(data)
        replay = mock.Mock(return_value=_report([row]))
        self.assertEqual(self._prepare(declaration)([row], self.directory, replay), {0})
        wrong_repo = replace(self.publication, repository="other-owner/SyntheticModel")
        for changed in (
            replace(declaration, record_sha256="0" * 64),
            replace(declaration, pointer=("other", "tokenizer_revision")),
            replace(declaration, match_span=(declaration.match_span[0] + 1, declaration.match_span[1])),
            replace(declaration, publication=wrong_repo),
            replace(declaration, publication=replace(self.publication, revision="0" * 40)),
        ):
            with self.subTest(changed=changed):
                replay = mock.Mock()
                self.assertEqual(self._prepare(changed)([row], self.directory, replay), set())
                replay.assert_not_called()

    def test_document_must_be_strict_and_fence_unambiguous(self) -> None:
        body = self._json()
        block = b"```json\n" + body + b"```\n"
        for markdown in (
            block + b"\n" + block, b"<!--\n" + block + b"-->\n", b"prose\n" + block,
            block.replace(b"```json", b"  ```json"), block.removesuffix(b"```\n"),
            b"\xff\n\n" + block,
        ):
            with self.subTest(markdown=markdown):
                declaration, row = self._record(markdown, path="probe.md")
                replay = mock.Mock()
                self.assertEqual(self._prepare(declaration)([row], self.directory, replay), set())
                replay.assert_not_called()
        duplicate_key = body.replace(b'"receipt":', b'"receipt": {}, "receipt":')
        declaration, row = self._record(duplicate_key)
        self.assertEqual(self._prepare(declaration)([row], self.directory, mock.Mock()), set())

    def test_disallowed_markers_at_every_markdown_line_boundary(self) -> None:
        block = b"```json\n" + self._json() + b"```\n"
        markers = {"backtick": b"\t````text", "tilde": b" ~~~~", "HTML": b"  <em>"}
        for boundary, surrounding, kind, placement in product(
            LINE_BREAKS, LINE_BREAKS, markers, ("before", "after"),
        ):
            with self.subTest(boundary=boundary, surrounding=surrounding, marker=kind, placement=placement):
                ending = LINE_BREAKS[surrounding]
                marker = markers[kind]
                prose = b"Ordinary prose" + ending + b"More prose" + LINE_BREAKS[boundary] + marker + ending
                markdown = prose + b"\n\n" + block if placement == "before" else block + prose
                expected = [marker, *FENCE_MARKERS] if placement == "before" else [*FENCE_MARKERS, marker]
                self.assertEqual(_markdown_markers(markdown), expected)
                self._assert_no_proof(*self._record(markdown, path="probe.md"))

    def test_html_comment_after_bare_cr_invalidates_a_fence_inside_it(self) -> None:
        markdown = b"Ordinary prose\r<!--\n\n```json\n" + self._json() + b"```\n-->\n"
        self.assertEqual(_markdown_markers(markdown), [b"<!--", *FENCE_MARKERS])
        self._assert_no_proof(*self._record(markdown, path="probe.md"))

    def test_mixed_markdown_prose_preserves_the_fenced_byte_occurrence(self) -> None:
        prose = "Café <em>inline HTML</em>".encode() + b"\rMore prose\r\nFinal line\n\n"
        body = self._json()
        for ending in (b"", b"\nTail\rFurther prose\r\n"):
            with self.subTest(ending=ending):
                prefix = prose + b"```json\n"
                markdown = prefix + body + b"```" + ending
                self.assertEqual(_markdown_markers(markdown), FENCE_MARKERS)
                declaration, row = self._record(markdown, path="probe.md")
                document = revision._Document.read(self.directory, declaration)
                self.assertIsNotNone(document)
                self.assertEqual(document.region, (len(prefix), len(prefix) + len(body)))
                replay = mock.Mock(return_value=_report([row]))
                self.assertEqual(self._prepare(declaration)([row], self.directory, replay), {0})
                replay.assert_called_once_with(["probe.md"], "--max-archive-depth=0", "--max-decode-depth=0")

    def test_markdown_fence_delimiters_require_lf(self) -> None:
        parts = (b"```json", self._json().removesuffix(b"\n"), b"```")
        positions = ("after opener", "before closer", "after closer")
        for boundary, position in product(("CR", "CRLF"), positions):
            with self.subTest(boundary=boundary, position=position):
                endings = dict.fromkeys(positions, b"\n")
                endings[position] = LINE_BREAKS[boundary]
                markdown = b"".join(
                    part + ending for part, ending in zip(parts, endings.values(), strict=True)
                )
                markdown += b"Ordinary prose\n"
                self.assertEqual(_markdown_markers(markdown), FENCE_MARKERS)
                self._assert_no_proof(*self._record(markdown, path="probe.md"))

    def test_archive_proof_validates_commit_and_regular_tree_assets(self) -> None:
        original = self.publication
        self.assertTrue(original.verified(self.reader.read))
        bad_trees = (
            self.tree.replace(b"100644 tokenizer.json", b"120000 tokenizer.json"),
            self.tree[:45], self.tree + self.tree, self.tree + b"bad",
        )
        malformed = [self._archive(tree) for tree in bad_trees]
        malformed.extend((
            self._archive(self.tree, headers=b"unexpected header\n"),
            self._archive(self.tree, tree_key=b"not-tree"),
        ))
        fresh = self._reader()
        for publication in malformed:
            with self.subTest(revision=publication.revision):
                self.assertIsNotNone(fresh.read(publication.commit.payload))
                self.assertIsNotNone(fresh.read(publication.tree.payload))
                self.assertFalse(publication.verified(fresh.read))
        altered_tree = replace(original.tree, sha256="0" * 64)
        self.assertFalse(replace(original, tree=altered_tree).verified(self.reader.read))
        self.assertFalse(replace(original, tree=original.commit).verified(self.reader.read))
        operand = original.commit.payload
        unreachable = self.git(
            "commit-tree", f"{operand.commit}^{{tree}}", "-m", "outside HEAD",
        ).stdout.strip()
        unreachable_object = replace(original.commit, payload=replace(operand, commit=unreachable))
        self.assertFalse(replace(original, commit=unreachable_object).verified(self.reader.read))

    def test_archive_accepts_non_ascii_names_and_zero_timestamp(self) -> None:
        headers = (
            b"author Caf\xc3\xa9 <fixture@example.invalid> 0 -0430\n"
            b"committer " + IDENTITY + b"\n"
        )
        publication = self._archive(self.tree, headers=headers)
        declaration, row = self._record(publication=publication)
        replay = mock.Mock(return_value=_report([row]))
        self.assertEqual(self._prepare(declaration)([row], self.directory, replay), {0})
        replay.assert_called_once_with(["probe.json"], "--max-archive-depth=0", "--max-decode-depth=0")

    def test_archive_requires_well_formed_author_and_committer_identities(self) -> None:
        malformed = {
            "missing name": IDENTITY.replace(b"Synthetic Author", b""),
            "blank name": IDENTITY.replace(b"Synthetic Author", b" \t"),
            "angle bracket in name": IDENTITY.replace(b"Author", b"<Author"),
            "empty email": IDENTITY.replace(b"fixture@example.invalid", b""),
            "missing email brackets": IDENTITY.replace(b"<", b"").replace(b">", b""),
            "angle bracket in email": IDENTITY.replace(b"fixture", b"fixture<"),
            "whitespace in email": IDENTITY.replace(b"fixture", b"fix\tture"),
            "name separator": IDENTITY.replace(b" <", b"\t<"),
            "email separator": IDENTITY.replace(b"> ", b">\t"),
            "timestamp separator": IDENTITY.replace(b" +", b"\t+"),
            "missing timestamp": IDENTITY.replace(b"1690000000", b""),
            "signed timestamp": IDENTITY.replace(b"1690000000", b"-1690000000"),
            "timestamp leading zero": IDENTITY.replace(b"1690000000", b"01690000000"),
            "non-ASCII timestamp digit": IDENTITY.replace(b"1690000000", "１".encode()),
            "timezone sign": IDENTITY.removesuffix(b"+0000") + b"0000",
            "timezone width": IDENTITY + b"0",
            "timezone digit": IDENTITY.removesuffix(b"0") + b"Z",
            "carriage return": IDENTITY.replace(b"Synthetic", b"Syn\rthetic"),
            "NUL": IDENTITY.replace(b"Synthetic", b"Syn\0thetic"),
            "trailing bytes": IDENTITY + b" extra",
        }
        tree_id = self._git_oid("tree", self.tree)
        self.assertTrue(self.publication.verified(self.reader.read))
        for key, component in product((b"author", b"committer"), malformed):
            with self.subTest(key=key, component=component):
                identities = dict.fromkeys((b"author", b"committer"), IDENTITY)
                identities[key] = malformed[component]
                headers = b"".join(name + b" " + value + b"\n" for name, value in identities.items())
                publication = self._archive(self.tree, headers=headers)
                self.reader = self._reader()
                read_blob = self.reader.read
                self.assertIsNotNone(publication.commit.read(read_blob, "commit", publication.revision))
                self.assertIsNotNone(publication.tree.read(read_blob, "tree", tree_id))
                self.assertFalse(publication.verified(read_blob))
                self._assert_no_proof(*self._record(publication=publication))

    def test_document_binds_only_the_occurrence_inside_the_fence(self) -> None:
        spelling = MATCH_PREFIX + self.publication.revision.encode() + b'"'
        data = b'"' + spelling + b"\n\n```json\n" + self._json() + b"```\n"
        outside, prose_row = self._record(data, path="probe.md")
        document = revision._Document.read(self.directory, outside)
        self.assertIsNotNone(document)
        self.assertFalse(document.proves(prose_row, outside))
        start = data.rindex(spelling)
        inside = replace(outside, match_span=(start, start + len(spelling)))
        self.assertTrue(document.proves(_scanner_row(inside.record, data, inside.match_span), inside))

    def test_direct_replay_requires_a_single_identical_raw_row(self) -> None:
        declaration, row = self._record()
        verify = self._prepare(declaration)
        changed = dict(row, Entropy=4.1)
        for response in (_report([]), _report([row, row]), _report([changed]), _report([], exit_code=1)):
            with self.subTest(response=response):
                self.assertEqual(verify([row], self.directory, mock.Mock(return_value=response)), set())
        self.assertEqual(verify([row, row], self.directory, mock.Mock(return_value=_report([row]))), set())
        for transformed in (dict(row, Tags=["decoded"]), dict(row, SymlinkFile="substitute.json")):
            self.assertEqual(verify([transformed], self.directory, mock.Mock()), set())

    def test_parser_rejects_duplicate_record_unsafe_url_and_non_revision_pointer(self) -> None:
        declaration, _ = self._record()
        row = _settings(declaration)
        for rows in (
            [row, row], [dict(row, pointer="/receipt/tokenizer")], [dict(row, record="probe.json.gz")],
            [dict(row, publication=dict(row["publication"], repository_url="https://huggingface.co@elsewhere.invalid"))],
            [dict(row, publication=dict(row["publication"], revision="HEAD"))],
        ):
            with self.subTest(rows=rows), self.assertRaises(ConfigError):
                adapters._secrets_spec(
                    {"public_git_revision_v1": rows}, self.repo, self.config_path, "checks.secrets",
                )

    def _cli(self, trusted: Path | None = None, *options: str):
        tool = tools.load_tools(GATE / "tools.lock.toml")["betterleaks"]
        if not tools._tool_binary(tool, tools._tools_dir()).exists():
            self.skipTest("pinned Betterleaks is absent")
        cache = tools.tool_binary("betterleaks").resolve().parent.parent
        args = ("--only", "secrets") if trusted is None else ("--policy-from", str(trusted))
        result = self.run_qg_process("check", "--json", *args, *options, env={"QG_TOOLS_DIR": str(cache)})
        check = self.check_by_id(self.parse_json(result), "secrets")
        self.assertNotIn(self.publication.revision, result.stdout + result.stderr)
        self.assertNotIn(_synthetic_credential(), result.stdout + result.stderr)
        return result, check

    def test_trusted_command_verifies_only_the_anchored_rows_and_retains_adjacent_findings(self) -> None:
        plain, _ = self._record(self._json(beside=', "access_token": "' + _synthetic_credential() + '"'))
        md, _ = self._record(b"# Synthetic\n\n```json\n" + self._json() + b"```\n", path="probe.md")
        for declaration in (plain, md):
            self.add_file(declaration.record, (self.directory / declaration.record).read_bytes())
        self.write_config(_config())
        self.commit_all()
        empty = self.trusted_directory("HEAD")
        self.write_config(_config(plain, md))

        plain_run, standalone = self._cli()
        self.assertEqual(plain_run.returncode, 1, plain_run.stderr)
        self.assertNotIn("verified_public_git_revisions", standalone.get("measurement") or {})
        repin, candidate = self._cli(empty, "--allow-protected", "quality-gate.toml")
        self.assertEqual(repin.returncode, 1, repin.stderr)
        self.assertNotIn("verified_public_git_revisions", candidate.get("measurement") or {})

        self.commit_all()
        trusted = self.trusted_directory("HEAD", "trusted-revisions")
        result, check = self._cli(trusted)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(check["reason"], "Betterleaks reported 1 unresolved finding(s)")
        self.assertIn("RuleID: github-pat", result.stderr)
        self.assertNotIn("RuleID: generic-api-key", result.stderr)
        self.assertEqual(check["measurement"]["verified_public_git_revisions"], 2)
        self.assertEqual({row["path"] for row in check["measurement"]["public_git_revision_locations"]},
                         {plain.record, md.record})

        self.add_file(md.record, (self.directory / md.record).read_bytes() + b"Unrelated edit.\n")
        changed, checked = self._cli(trusted)
        self.assertIn("RuleID: generic-api-key", changed.stderr)
        self.assertEqual(checked["measurement"]["verified_public_git_revisions"], 1)
