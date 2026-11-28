"""One adapter descriptor drives parsing, running, display, direction and verification."""
from __future__ import annotations

import ast
import contextlib
import dataclasses
import importlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from support import GATE, FixtureCase, baseline_text, stub_check_result, with_clones
from test_python_tests import tests_config

import hashlib
import json
import re

from quality_gate import elisp_lint, elisp_tests, python_crap, trust, worklist
from quality_gate.files import DiffBaseOverride
from quality_gate.python_tests import _parse_python_tests
from quality_gate.runner import Diagnostics, RunResult

sys.path.insert(0, str(GATE))
adapters = importlib.import_module("quality_gate.adapters")
checks = importlib.import_module("quality_gate.checks")
policy = importlib.import_module("quality_gate.policy")
gate_result = importlib.import_module("quality_gate.gate_result")
ratchet = importlib.import_module("quality_gate.ratchet")


@dataclasses.dataclass(frozen=True)
class StubSpec:
    count: int


def parse_stub(
    raw: dict[str, object], root: Path, path: Path, full_key: str
) -> adapters.ParsedSpec:
    count = policy._integer(raw, "count", path, f"{full_key}.count")
    baseline = (
        adapters._baseline(raw, root, path, full_key)
        if "baseline" in raw
        else None
    )
    return adapters.ParsedSpec(
        StubSpec(count), "stub/1", ("tests",), threshold=0, baseline=baseline
    )


def run_stub(context: adapters.AdapterContext) -> checks.CheckResult:
    check = context.check
    return stub_check_result(
        check, 600, tests_ran=check.spec.count, tests_skipped=0
    )


def floor_entry_direction(subject: str, configured: str) -> str:
    return "min" if subject == "floor-subject" else configured


STUB = adapters.AdapterDescriptor(
    "stub",
    ("count",),
    parse_stub,
    run_stub,
    runs_suite=False,
    display=lambda value: f"{value:.2f}",
    budget=lambda spec: 3,
    entry_direction=floor_entry_direction,
)


FLOOR_STUB = adapters.AdapterDescriptor(
    "floor-stub",
    ("count", "baseline"),
    parse_stub,
    run_stub,
    runs_suite=False,
    default_direction="max",
    budget=lambda spec: 3,
    entry_direction=floor_entry_direction,
)

STUB_CONFIG = """\
schema = 2

[code]
patterns = ["*.py"]
shebangs = []

[classes.python]
code = true
description = "Python source"
checks = ["stub"]

[checks.stub]
adapter = "stub"
tier = 1
enforcement = "enforced"
count = 4
"""

FLOOR_CONFIG = """\
schema = 2

[code]
patterns = ["*.py"]
shebangs = []

[classes.python]
code = true
description = "Python source"
checks = ["floor"]

[checks.floor]
adapter = "floor-stub"
tier = 1
enforcement = "enforced"
count = 4
baseline = "floor.toml"
"""

VERIFICATION_CONFIG = """\
schema = 2

[code]
patterns = ["*.py"]
shebangs = []

[classes.python]
code = true
description = "Python source"
checks = ["stub", "verification"]

[checks.stub]
adapter = "stub"
tier = 1
enforcement = "enforced"
count = 4

[checks.verification]
adapter = "verification"
tier = 1
enforcement = "enforced"
baseline = "verification.toml"
"""

COVERAGE_CONFIG = STUB_CONFIG.replace(
    'checks = ["stub"]', 'checks = ["python-measure", "elisp-measure"]',
).split("[checks.stub]")[0] + r"""
[checks.python-suite]
adapter = "python_tests"
tier = 1
enforcement = "enforced"
run = ["python3", "-m", "unittest"]
tests_pattern = 'Ran (\d+) tests'

[checks.python-measure]
adapter = "python_crap"
tier = 1
enforcement = "enforced"
requires = "python-suite"

[checks.elisp-suite]
adapter = "elisp_tests"
tier = 1
enforcement = "enforced"
suite = "suite.el"

[checks.elisp-measure]
adapter = "elisp_crap"
tier = 1
enforcement = "enforced"
requires = "elisp-suite"

[checks.bridge]
adapter = "coverage-bridge"
tier = 1
enforcement = "enforced"
requires = "elisp-measure"

[checks.verify]
adapter = "verification"
tier = 1
enforcement = "enforced"
requires = "bridge"
"""


def parse_coverage_bridge(
    raw: dict[str, object], _root: Path, path: Path, full_key: str,
) -> adapters.ParsedSpec:
    requires = policy._string(raw, "requires", path, f"{full_key}.requires")
    return adapters.ParsedSpec(StubSpec(1), "stub/1", ("tests",), requires=requires)


def _package_imports(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                names = (
                    [f"quality_gate.{node.module}"] if node.module
                    else [f"quality_gate.{alias.name}" for alias in node.names]
                )
            elif node.module == "quality_gate":
                names = [f"quality_gate.{alias.name}" for alias in node.names]
            else:
                names = [node.module or ""]
        else:
            continue
        for name in names:
            if name.startswith("quality_gate."):
                yield name.split(".")[1]


class ArchitectureTests(unittest.TestCase):
    def test_core_imports_only_core_modules(self) -> None:
        core = {
            "__init__", "adapters", "checks", "cli", "files", "gate_result",
            "json_input", "output_patterns", "payload", "policy", "ratchet", "regexrun",
            "runner", "tools", "trust", "worklist",
        }
        for module in sorted(core | {"qg"}):
            path = GATE / "qg.py" if module == "qg" else GATE / "quality_gate" / f"{module}.py"
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for imported in _package_imports(tree):
                if module != "adapters":
                    with self.subTest(module=module, imported=imported):
                        self.assertIn(
                            imported, core,
                            f"{path.relative_to(GATE)} imports quality_gate.{imported} outside the core",
                        )


class PolicyAdapterBoundaryTests(FixtureCase):
    def run_adapter(self, config, identifier, classes, prior=None):
        return checks.run_check(
            self.repo, config, config.checks[identifier], list(classes), classes,
            prefix=identifier, evidence_dir=self.repo, prior=prior,
        )

    def crap_policy(self):
        text = COVERAGE_CONFIG.split("[checks.elisp-suite]")[0].replace(
            'checks = ["python-measure", "elisp-measure"]',
            'checks = ["python-measure", "other-measure", "verify"]',
        )
        self.write_config(text + r"""
threshold = 0

[classes.left]
code = true
description = "First CRAP selection"
checks = ["python-measure"]

[classes.right]
code = true
description = "Second CRAP selection"
checks = ["other-measure"]

[checks.other-suite]
adapter = "python_tests"
tier = 1
enforcement = "enforced"
run = ["python3", "-m", "unittest"]
tests_pattern = 'Ran (\d+) tests'

[checks.other-measure]
adapter = "python_crap"
tier = 1
enforcement = "enforced"
requires = "other-suite"

[checks.verify]
adapter = "verification"
tier = 1
enforcement = "enforced"
requires = "python-suite"
""")
        return policy.load_config(self.repo)

    def crap_evidence(self, config, suites):
        coverage_config = self.add_file("coverage.ini", "fixture settings")
        prior = {}
        for suite in suites:
            evidence = self.add_file(suite + ".coverage", suite)
            prior[suite] = stub_check_result(
                config.checks[suite], 600, tests_ran=1, tests_skipped=0,
                evidence_path=evidence,
                adapter_data={"coverage_config": coverage_config, "coverage_settings": suite},
            )
        return prior

    def coverage_double(self, analyses):
        def coverage(config_file):
            excluded_by_path = analyses[config_file]

            def analyse(filename):
                path = Path(filename).relative_to(self.repo).as_posix()
                excluded = excluded_by_path[path]
                statements = sorted({1, 2, 3, 4} - set(excluded))
                return filename, statements, excluded, [], ""

            return SimpleNamespace(
                load=lambda: None, analysis2=analyse,
                get_data=lambda: SimpleNamespace(lines=lambda _filename: [1, 2, 3, 4]),
            )

        return SimpleNamespace(Coverage=coverage, CoverageException=RuntimeError)

    @contextlib.contextmanager
    def fake_coverage(self, analyses):
        with (
            mock.patch.object(python_crap, "import_coverage", return_value=self.coverage_double(analyses)),
            mock.patch.object(python_crap, "coverage_config_data", side_effect=lambda settings, _: settings),
        ):
            yield

    def assert_exclusion_map(self, actual, expected, label):
        self.assertIsNotNone(actual, label)
        self.assertEqual(set(actual), set(expected), label)
        for path, lines in expected.items():
            self.assertTupleEqual(actual[path], lines, f"{label} {path}")

    def assert_no_cover_findings(self, result, expected):
        findings = [row for row in result.findings if row.subject.endswith(":no-cover")]
        subjects = {f"exclusions:{path}:no-cover": path for path in expected}
        self.assertCountEqual([row.subject for row in findings], subjects)
        for row in findings:
            path = subjects[row.subject]
            lines = expected[path]
            self.assertEqual(row.value, len(lines), path)
            self.assertEqual(row.location, f"{path}:{lines[0]}" if lines else path, path)
            self.assertEqual(
                [(item.path, item.start_line, item.end_line) for item in row.locations],
                [(path, line, line) for line in lines], path,
            )

    def test_crap_and_verification_use_coverage_owned_exclusions(self):
        config = self.crap_policy()
        source = (
            "def example(flag):\n    if flag:\n        return 1\n    return 0\n"
            "\n# Outside all subjects\n"
        )
        classes = {"shared.py": "python", "clean.py": "left", "empty.py": "left", "right.py": "right"}
        ownership = {path: set() if path == "empty.py" else {1, 2, 3, 4} for path in classes}
        for path, lines in ownership.items():
            self.add_file(path, source if lines else "# No measured subjects\n")
        analyses = {
            "python-suite": {"shared.py": [6, 3, 3], "clean.py": [6]},
            "other-suite": {"shared.py": [4], "right.py": [3]},
        }
        selections = {"python-measure": {"left", "python"}, "other-measure": {"right", "python"}}
        prior = self.crap_evidence(config, analyses)
        expected_union = {}
        with self.fake_coverage(analyses):
            for identifier, selected in selections.items():
                result = self.run_adapter(config, identifier, classes, prior)
                analysis = analyses[config.checks[identifier].spec.requires]
                expected = {
                    path: tuple(sorted(owned & set(analysis[path])))
                    for path, owned in ownership.items() if owned and classes[path] in selected
                }
                self.assert_exclusion_map(result.excluded_lines, expected, identifier)
                self.assertNotIn("excluded_lines", result.to_json(), identifier)
                for path, lines in expected.items():
                    expected_union.setdefault(path, set()).update(lines)
                prior[identifier] = result
        failing = prior["python-measure"]
        self.assertEqual(failing.outcome, "fail", failing.reason)
        self.assertTrue(all(item.measurement and item.locations for item in failing.findings))
        stripped = {
            identifier: dataclasses.replace(
                prior[identifier],
                findings=[dataclasses.replace(row, measurement=None, locations=None)
                          for row in prior[identifier].findings],
            )
            for identifier in selections
        }
        measured = self.run_adapter(config, "verify", classes, prior | stripped)
        self.assert_no_cover_findings(
            measured, {path: tuple(sorted(lines)) for path, lines in expected_union.items()},
        )
        unavailable = dataclasses.replace(failing, excluded_lines=None)
        for prior_results, detail in (
            (prior | {"python-measure": unavailable}, "reported no measurement"),
            ({key: value for key, value in prior.items() if key != "python-measure"}, "did not run"),
        ):
            with self.subTest(detail=detail):
                result = self.run_adapter(config, "verify", classes, prior_results)
                self.assertEqual(result.outcome, "error", result.reason)
                self.assertIn(f"python-measure {detail}", result.reason)

    def test_crap_discards_partial_analysis(self):
        source = "def example(flag):\n    if flag:\n        return 1\n    return 0\n"
        analyses = {"python-suite": {"first.py": [3], "second.py": [2, 3, 4]}}
        files = list(analyses["python-suite"])
        for path in files:
            self.add_file(path, source)
        evidence = self.add_file("fixture.coverage", "")
        with self.fake_coverage(analyses):
            measurement = python_crap.measure_crap(self.repo, files, evidence, "python-suite")
        self.assertEqual(len(measurement.failures), 1, measurement.failures)
        self.assertIn("second.py:example: unmeasured", measurement.failures[0])
        self.assertEqual(measurement.findings, [])
        self.assertIsNone(measurement.excluded_lines)

    def test_verification_accepts_an_empty_map_or_no_crap_checks(self):
        config = self.crap_policy()
        classes = {"empty.py": "python"}
        self.add_file("empty.py", "# No measured subjects\n")
        analyses = {"python-suite": {}, "other-suite": {}}
        prior = self.crap_evidence(config, analyses)
        with self.fake_coverage(analyses):
            for identifier in ("python-measure", "other-measure"):
                result = self.run_adapter(config, identifier, classes, prior)
                self.assert_exclusion_map(result.excluded_lines, {}, identifier)
                prior[identifier] = result
        measured = self.run_adapter(config, "verify", classes, prior)
        self.assertIsNotNone(measured.ratchet, measured.reason)
        self.assert_no_cover_findings(measured, {})
        without_crap = dataclasses.replace(config, checks={
            name: check for name, check in config.checks.items() if check.adapter != "python_crap"
        })
        prior["python-measure"] = dataclasses.replace(
            prior["python-measure"], excluded_lines={"outside.py": (2,)},
        )
        measured = self.run_adapter(without_crap, "verify", classes, prior)
        self.assertIsNotNone(measured.ratchet, measured.reason)
        self.assert_no_cover_findings(measured, {})

    def assert_declarations(self, actual, expected):
        self.assertEqual(set(actual), set(expected))
        self.assertEqual(list(actual), list(expected), "baseline declaration order")
        for identifier, value in expected.items():
            self.assertEqual(actual[identifier], value, identifier)

    def write_debt_policy(self, source, names):
        text = FLOOR_CONFIG.split("[checks.floor]")[0]
        declaration = FLOOR_CONFIG[FLOOR_CONFIG.index("[checks.floor]"):]
        for identifier, spelling in names.items():
            text += "\n" + declaration.replace("[checks.floor]", f"[checks.{identifier}]").replace(
                '"floor.toml"', json.dumps(spelling),
            )
            self.add_file(spelling, baseline_text([], check=identifier, metric_version="stub/1"))
        raw = (f"# {source}\n" + text).encode("utf-8")
        self.config_path.write_bytes(raw)
        return raw

    def debt_report(self, revision):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = worklist.command_debt(self.repo, revision, True)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_missing_policy_preserves_each_callers_diagnostic(self):
        self.config_path.unlink()
        with self.assertRaises(FileNotFoundError) as read_error:
            self.config_path.read_bytes()
        with self.assertRaises(policy.ConfigError) as load_error:
            policy.load_config(self.repo)
        self.assertEqual(
            str(load_error.exception), f"{self.config_path}: expected a configuration file, got missing",
        )
        code, stdout, stderr = self.debt_report(None)
        self.assertEqual((code, stdout), (2, ""), stderr)
        self.assertEqual(
            stderr,
            f"debt: {self.config_path}: expected a readable configuration file, got {read_error.exception}\n",
        )

    def test_unreadable_policy_preserves_the_shared_diagnostic(self):
        self.config_path.unlink()
        self.config_path.mkdir()
        with self.assertRaises(IsADirectoryError) as read_error:
            self.config_path.read_bytes()
        expected = f"{self.config_path}: expected a readable configuration file, got {read_error.exception}"
        with self.assertRaises(policy.ConfigError) as load_error:
            policy.load_config(self.repo)
        self.assertEqual(str(load_error.exception), expected)
        code, stdout, stderr = self.debt_report(None)
        self.assertEqual((code, stdout), (2, ""), stderr)
        self.assertEqual(stderr, f"debt: {expected}\n")

    def assert_debt_delegation(self, revision, raw, label, names, reader_calls):
        with (
            mock.patch.object(policy, "read_policy", wraps=policy.read_policy) as reader,
            mock.patch.object(policy, "decode_policy", wraps=policy.decode_policy) as decode,
            mock.patch.object(policy, "raw_baselines", wraps=policy.raw_baselines) as discover,
        ):
            code, stdout, stderr = self.debt_report(revision)
        self.assertEqual(code, 0, stderr)
        reader.assert_has_calls(reader_calls)
        self.assertEqual(reader.call_count, len(reader_calls))
        decode.assert_called_once_with(raw, label)
        discover.assert_called_once()
        rows = json.loads(stdout)["checks"]
        self.assertEqual([row["id"] for row in rows], list(names))
        self.assert_declarations({row["id"]: row["baseline"] for row in rows}, names)

    def test_policy_sources_share_decoding_and_preserve_baseline_declarations(self):
        revision_names = {"floor": "./rev//z.toml", "rev-only": "rev/./a.toml"}
        revision_raw = self.write_debt_policy("requested revision", revision_names)
        self.commit_all()
        sha = self.git("rev-parse", "HEAD").stdout.strip()
        trusted_names = {"floor": "./trusted//z.toml", "trusted-only": "trusted/./a.toml"}
        trusted_raw = self.write_debt_policy("trusted source", trusted_names)
        self.add_file("tools.lock.toml", "")
        self.commit_all()
        trusted_root = self.trusted_directory("HEAD")
        working_names = {"floor": "./current//z.toml", "current-only": "current/./a.toml"}
        working_raw = self.write_debt_policy("working tree", working_names)
        with (
            mock.patch.object(adapters, "ADAPTERS", {**adapters.ADAPTERS, FLOOR_STUB.name: FLOOR_STUB}),
            mock.patch.object(policy, "read_policy", wraps=policy.read_policy) as reader,
            mock.patch.object(policy, "decode_policy", wraps=policy.decode_policy) as decode,
        ):
            config = policy.load_config(self.repo)
            reader.assert_called_once_with(self.config_path)
            decode.assert_called_once_with(working_raw, str(self.config_path))
            self.assertEqual(list(config.checks), list(working_names))
            decode.reset_mock()
            with mock.patch.object(policy, "raw_baselines", wraps=policy.raw_baselines) as discover:
                prepared = trust.prepare_trust(self.repo, str(trusted_root), [])
                self.addCleanup(prepared.close)
            decode.assert_called_once_with(trusted_raw, f"{self.config_path} at {trusted_root}")
            discover.assert_called_once()
            self.assert_declarations(policy.raw_baselines(discover.call_args.args[0]), trusted_names)
            staged = prepared.rev_config.path.parent
            self.assertEqual(prepared.rev_config.path.read_bytes(), trusted_raw)
            self.assertEqual(
                {path.relative_to(staged).as_posix() for path in staged.rglob("*.toml")},
                {"quality-gate.toml", *(Path(name).as_posix() for name in trusted_names.values())},
            )
            for identifier, spelling in trusted_names.items():
                self.assertEqual(
                    prepared.rev_config.checks[identifier].baseline, staged / spelling, identifier,
                )
                self.assertEqual(
                    (staged / spelling).read_bytes(), (trusted_root / spelling).read_bytes(), identifier,
                )
            self.assert_debt_delegation(None, working_raw, str(self.config_path), working_names,
                                        [mock.call(self.config_path)])
            self.assert_debt_delegation(sha, revision_raw, f"{sha} ({sha}):quality-gate.toml",
                                        revision_names, [])

    def test_effective_policy_keeps_the_digest_of_the_bytes_decoded(self):
        trusted_raw = self.write_debt_policy("trusted source", {"floor": "./trusted//z.toml"})
        self.add_file("tools.lock.toml", "")
        self.commit_all()
        source = self.trusted_directory("HEAD")
        working_raw = self.write_debt_policy("working tree", {"floor": "./current//z.toml"})
        decode = policy.decode_policy

        def replace_after_decode(raw, label):
            decoded = decode(raw, label)
            self.config_path.write_bytes(working_raw + b"\n# changed after decoding\n")
            return decoded

        with mock.patch.dict(adapters.ADAPTERS, {FLOOR_STUB.name: FLOOR_STUB}):
            with mock.patch.object(policy, "decode_policy", side_effect=replace_after_decode) as decoder:
                config = policy.load_config(self.repo)
            decoder.assert_called_once_with(working_raw, str(self.config_path))
            self.assertEqual(config.policy_sha256, hashlib.sha256(working_raw).hexdigest())
            self.config_path.write_bytes(working_raw)
            for allowed, effective in (([], trusted_raw), (["quality-gate.toml"], working_raw)):
                with self.subTest(allowed=allowed):
                    prepared = trust.prepare_trust(self.repo, str(source), allowed)
                    self.addCleanup(prepared.close)
                    self.assertEqual(prepared.config.policy_sha256, hashlib.sha256(effective).hexdigest())

    def test_raw_baselines_leave_malformed_declarations_to_validation(self):
        names = {"floor": "./baselines//floor.toml"}
        raw = self.write_debt_policy("raw declarations", names)
        raw = raw.replace(b"[checks.floor]", b"[checks]\nscalar = false\n\n[checks.floor]")
        raw += (
            b'\n[checks.invalid]\nadapter = "floor-stub"\ntier = 1\n'
            b'enforcement = "enforced"\ncount = 4\nbaseline = 42\n'
        )
        self.config_path.write_bytes(raw)
        data = policy.decode_policy(raw, str(self.config_path))
        self.assert_declarations(policy.raw_baselines(data), names)
        with self.assertRaisesRegex(policy.ConfigError, r"checks\.scalar"):
            policy.load_config(self.repo)
        self.config_path.write_bytes(raw.replace(b"scalar = false\n", b""))
        with mock.patch.dict(adapters.ADAPTERS, {FLOOR_STUB.name: FLOOR_STUB}):
            with self.assertRaisesRegex(policy.ConfigError, r"checks\.invalid\.baseline"):
                policy.load_config(self.repo)

    def test_invalid_policy_bytes_report_the_selected_source(self):
        for raw in (b"\xff", b"[invalid"):
            with self.subTest(raw=raw):
                self.config_path.write_bytes(raw)
                self.commit_all()
                sha = self.git("rev-parse", "HEAD").stdout.strip()
                trusted_root = self.trusted_directory(sha, name=f"trusted-{sha}")
                with self.assertRaises(policy.ConfigError) as invalid:
                    policy.load_config(self.repo)
                self.assertIn(f"{self.config_path}: expected valid TOML", str(invalid.exception))
                with self.assertRaises(policy.UsageError) as invalid:
                    trust.prepare_trust(self.repo, str(trusted_root), [])
                self.assertIn(
                    f"{self.config_path} at {trusted_root}: expected valid TOML", str(invalid.exception),
                )
                labels = {None: str(self.config_path), sha: f"{sha} ({sha}):quality-gate.toml"}
                for revision, label in labels.items():
                    code, stdout, stderr = self.debt_report(revision)
                    self.assertEqual((code, stdout), (2, ""), stderr)
                    self.assertIn(f"{label}: expected valid TOML", stderr)

    def lint_child(self, mode, expected_batches, report_mode, *, finding=False):
        def child(argv, **_kwargs):
            form = argv[-1]
            self.assertEqual(form.split(" ", 1)[0], f"(qg-elisp-lint-{mode}", mode)
            names = [json.loads(value) for value in re.findall(r'"[^"]*"', form)]
            parts = 2 if mode == "compile" else 1
            batch = names[:-parts]
            self.assertEqual(batch, expected_batches.pop(0), mode)
            report = {
                "emacs_version": "30.1", "mode": report_mode, "files": batch, "failed": [], "issues": [],
            }
            if finding and mode == "compile":
                report["failed"] = batch
            if finding and mode == "checkdoc":
                report["issues"] = [{"file": batch[-1], "line": 3, "message": "missing docstring"}]
            Path(names[-1]).write_text(json.dumps(report), encoding="utf-8")
            return RunResult(tuple(argv), "completed", 0, stderr=b"compiler warning")

        return child

    def test_lint_registration_binds_mode_independently_of_descriptor_name(self):
        compile_descriptor = adapters.ADAPTERS["elisp_compile"]
        checkdoc_descriptor = adapters.ADAPTERS["elisp_checkdoc"]
        self.assertIs(compile_descriptor.parse, checkdoc_descriptor.parse)
        classes = {"first.el": "python", "second.el": "python"}
        for descriptor, mode, other, batches, diagnostics in (
            (compile_descriptor, "compile", "checkdoc", [["first.el"], ["second.el"]],
             ("first.el: compiler warning", "second.el: compiler warning")),
            (checkdoc_descriptor, "checkdoc", "compile", [list(classes)],
             ("second.el:3: missing docstring",)),
        ):
            with self.subTest(descriptor=descriptor.name), mock.patch.dict(adapters.ADAPTERS):
                self.assertIs(descriptor.keys, elisp_lint.LINT_KEYS, descriptor.name)
                alias = adapters.register_adapter(dataclasses.replace(descriptor, name="renamed-lint"))
                self.write_config(STUB_CONFIG.replace('adapter = "stub"', f'adapter = "{alias.name}"')
                                  .replace("count = 4", ""))
                config = policy.load_config(self.repo)
                probe = RunResult((), "completed", 0, stdout=b"30.1")
                with mock.patch.object(elisp_tests, "run", return_value=probe) as version_run:
                    for report_mode, finding, outcome in ((mode, True, "fail"), (mode, False, "pass"),
                                                          (other, False, "unsupported")):
                        remaining = list(batches)
                        with mock.patch.object(elisp_lint, "run", side_effect=self.lint_child(
                            mode, remaining, report_mode, finding=finding,
                        )):
                            result = self.run_adapter(config, "stub", classes)
                        self.assertEqual(result.outcome, outcome, f"{descriptor.name}: {result.reason}")
                        if outcome == "unsupported":
                            self.assertIn(f"valid {descriptor.name} report", result.reason, descriptor.name)
                            self.assertEqual(remaining, batches[1:], descriptor.name)
                        else:
                            self.assertEqual(remaining, [], descriptor.name)
                        if finding:
                            for detail in diagnostics:
                                self.assertIn(detail, result.reason, descriptor.name)
                    self.assertEqual(version_run.call_count, 3, descriptor.name)


class AdapterRegistrationTests(unittest.TestCase):
    def test_descriptor_has_no_language_version_fields(self) -> None:
        fields = {field.name for field in dataclasses.fields(adapters.AdapterDescriptor)}
        self.assertFalse({"minimum_emacs_version", "emacs_version", "minimum_python_version"} & fields)

    def test_fixed_or_configured_defaults_register_without_subject_rule(self) -> None:
        for default in (None, "max", "min"):
            with self.subTest(default=default), mock.patch.dict(adapters.ADAPTERS):
                descriptor = dataclasses.replace(
                    FLOOR_STUB,
                    default_direction=default, entry_direction=None,
                )
                self.assertIs(adapters.register_adapter(descriptor), descriptor)
                self.assertIs(adapters.adapter_for(descriptor.name), descriptor)
                for configured in ("max", "min"):
                    self.assertEqual(
                        descriptor.direction_for_subject("any-subject", configured),
                        default or configured,
                    )

    def test_shipped_adapters_register_unchanged(self) -> None:
        descriptors = tuple(adapters.ADAPTERS.values())
        modes = {
            "source_chars": "expanded",
            "python_crap": "expanded",
            "elisp_crap": "expanded",
            "comments": "expanded",
            "elisp_compile": "affected",
            "elisp_checkdoc": "affected",
        }
        self.assertEqual(
            {item.name: item.file_selection for item in descriptors},
            {name: modes.get(name) for name in adapters.ADAPTERS} | modes,
        )
        with mock.patch.dict(adapters.ADAPTERS, clear=True):
            for descriptor in descriptors:
                with self.subTest(adapter=descriptor.name):
                    self.assertIs(adapters.register_adapter(descriptor), descriptor)
                    self.assertIs(adapters.adapter_for(descriptor.name), descriptor)
            self.assertEqual(adapters.adapter_names(), tuple(item.name for item in descriptors))

    def assert_rejected(self, descriptor: adapters.AdapterDescriptor, field: str) -> None:
        before = tuple(adapters.ADAPTERS.items())
        with self.assertRaises(ValueError) as caught:
            adapters.register_adapter(descriptor)
        self.assertIn(descriptor.name, str(caught.exception))
        self.assertIn(field, str(caught.exception))
        self.assertEqual(adapters.adapter_names(), tuple(name for name, _ in before))
        for name, original in before:
            self.assertIs(adapters.ADAPTERS[name], original, name)

    def test_occupied_names_are_rejected(self) -> None:
        for name, descriptor in tuple(adapters.ADAPTERS.items()):
            with self.subTest(adapter=name):
                self.assert_rejected(descriptor, "duplicate name")
                self.assert_rejected(dataclasses.replace(STUB, name=name), "duplicate name")

    def test_invalid_metadata_is_rejected(self) -> None:
        descriptor = dataclasses.replace(STUB, name="unregistered-fixture")
        cases = [
            ("file_selection", "all"),
            ("file_selection", ["expanded"]),
            ("keys", ["count"]),
            ("keys", ("count", 42)),
            ("keys", ("count", "")),
            ("keys", ("count", " \t")),
            ("keys", ("count", "count")),
            *(("keys", ("count", key)) for key in policy.COMMON_CHECK_KEYS),
            ("budget", 10),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                self.assert_rejected(dataclasses.replace(descriptor, **{field: value}), field)

    def test_registration_leaves_the_budget_provider_unevaluated(self) -> None:
        def budget(spec: StubSpec) -> int:
            return spec.count

        provider = mock.Mock(wraps=budget)
        descriptor = dataclasses.replace(STUB, name="lazy-budget-fixture", budget=provider)
        with mock.patch.dict(adapters.ADAPTERS):
            self.assertIs(adapters.register_adapter(descriptor), descriptor)
            self.assertIs(adapters.adapter_for(descriptor.name), descriptor)
            provider.assert_not_called()


class CheckDependencyTests(unittest.TestCase):
    def earlier(self) -> list[SimpleNamespace]:
        return [
            SimpleNamespace(
                id="lint", adapter="command", evidence=("static",)
            ),
            SimpleNamespace(
                id="unit", adapter="python_tests", evidence=("tests",)
            ),
            SimpleNamespace(
                id="crap", adapter="python_crap", evidence=("crap",)
            ),
            SimpleNamespace(
                id="acceptance", adapter="python_tests", evidence=("tests",)
            ),
        ]

    def descriptor(self, *, requires_tests: bool) -> adapters.AdapterDescriptor:
        return adapters.AdapterDescriptor(
            "stub", (), parse_stub, run_stub, requires_tests=requires_tests,
            runs_suite=False,
        )

    def test_test_dependencies_use_the_configured_check(self) -> None:
        self.assertEqual(
            checks._test_check_dependencies("tests", self.earlier()),
            ["tests"],
        )

    def test_test_dependencies_take_each_earlier_test_producer(self) -> None:
        self.assertEqual(
            checks._test_check_dependencies(None, self.earlier()),
            ["unit", "acceptance"],
        )

    def test_required_checks_adds_earlier_crap_checks(self) -> None:
        self.assertEqual(
            self.descriptor(requires_tests=True).required_checks(
                None, self.earlier()
            ),
            ("unit", "acceptance", "crap"),
        )

    def test_required_checks_without_tests_keeps_its_own_requires(self) -> None:
        descriptor = self.descriptor(requires_tests=False)
        self.assertEqual(
            descriptor.required_checks("tests", self.earlier()), ("tests",)
        )
        self.assertEqual(descriptor.required_checks(None, self.earlier()), ())


class PythonTestsAdapterTests(FixtureCase):
    def test_invalid_run_argument_names_the_full_policy_key(self) -> None:
        with self.assertRaisesRegex(policy.ConfigError, r"checks\.tests\.run\[0\].*embedded NUL"):
            _parse_python_tests({"run": ["\0"]}, self.config_path, "checks.tests")

    def test_unavailable_evidence_directory_fails_the_check(self) -> None:
        self.write_config(tests_config())
        config = policy.load_config(self.repo)
        evidence_dir = self.base / "missing"
        with contextlib.redirect_stderr(io.StringIO()):
            result = checks.run_check(
                self.repo, config, config.checks["tests"], [], {},
                prefix="check: tests", evidence_dir=evidence_dir,
            )
        self.assertEqual((result.outcome, result.execution), ("error", "error"))
        self.assertIn("cannot create coverage data directory", result.reason)
        self.assertIn(str(evidence_dir / "data"), result.reason)


class StubAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        adapters.register_adapter(STUB)
        self.addCleanup(adapters.remove_adapter, "stub")
        temporary = tempfile.TemporaryDirectory(prefix="qg-stub-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "a.py").write_text("VALUE = 1\n", encoding="utf-8")

    def config(self, text: str) -> policy.Config:
        (self.root / "quality-gate.toml").write_text(text, encoding="utf-8")
        return policy.load_config(self.root)

    def test_adapter_context_requires_keyword_inventory(self) -> None:
        config = self.config(STUB_CONFIG)
        args = (self.root, config, config.checks["stub"], ["a.py"], {}, "stub", {}, self.root)
        with self.assertRaisesRegex(TypeError, "keyword-only argument: 'inventory_files'"):
            adapters.AdapterContext(*args)

    def test_elisp_crap_uses_the_longest_inventory_path_for_baseline_subjects(self) -> None:
        selected_path = "lisp/calc.el"
        unselected_path = "lisp/calc.el:variant.el"
        context = adapters.AdapterContext(
            self.root, None, None, [selected_path], {}, "elisp-crap", {}, self.root,
            inventory_files=[selected_path, unselected_path],
        )
        selected = f"{selected_path}:compute"
        unselected = f"{unselected_path}:compute"
        entries = [ratchet.BaselineEntry(subject, 1, "reviewed") for subject in (selected, unselected)]
        domain = adapters.elisp_crap._domain(context, [selected_path], entries)
        self.assertEqual(domain.subjects, (selected,))

    def test_clone_baseline_sees_inventory_outside_the_planned_inputs(self) -> None:
        (self.root / "README.md").write_text("Fixture documentation.\n", encoding="utf-8")
        (self.root / "quality-gate-clones.toml").write_text(
            baseline_text([{
                "subject": "fp-present", "files": ["a.py", "README.md"], "reason": "reviewed",
            }]),
            encoding="utf-8",
        )
        config = self.config(with_clones())
        check = config.checks["clones"]
        classes = {"a.py": "python", "README.md": "doc"}
        graph = (set(classes), {"a.py": "changed"}, {"a.py": "changed"})
        measurement = adapters.clones.CloneMeasurement([], Diagnostics(), "completed")
        for changed in (None, {"a.py"}):
            with (
                self.subTest(changed=changed),
                mock.patch.object(adapters.clones, "measure_clones", return_value=measurement) as measure,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                document = self.run_selection(config, check, classes, changed, graph).to_json()
                measure.assert_called_once()
                self.assertEqual(measure.call_args.args[1], {"a.py": "python"})
                self.assertEqual(document["resolved_baseline_entries"], [])
                self.assertEqual(document["unmeasured_baseline_entries"], ["fp-present"])

    def test_descriptor_selection_controls_the_runner_and_report(self) -> None:
        initializer, seed = "pkg/__init__.py", "pkg/seed.py"
        dependent, unrelated, external = "consumer.py", "unrelated.py", "external.py"
        classes = dict.fromkeys((initializer, seed, dependent, unrelated), "python") | {external: "other"}
        expanded = {initializer: "changed", seed: f"package initializer {initializer} changed"}
        affected = expanded | {dependent: f"depends on {seed}", external: f"depends on {dependent}"}
        graph = (set(classes), expanded, affected)
        incomplete_graph = (set(classes) - {unrelated}, expanded, affected)
        for name, mode, reasons in (
            ("fixture-expand", "expanded", expanded),
            ("fixture-depend", "affected", affected),
            ("fixture-full", None, {}),
        ):
            runner = mock.Mock(side_effect=self.run_selection_stub)
            descriptor = dataclasses.replace(STUB, name=name, file_selection=mode, run=runner)
            adapters.register_adapter(descriptor)
            self.addCleanup(adapters.remove_adapter, name)
            config = self.config(STUB_CONFIG.replace('adapter = "stub"', f'adapter = "{name}"') + """
[classes.other]
code = true
description = "Other source"
""")
            check = config.checks["stub"]
            inputs = {
                path for path, class_name in classes.items()
                if check.id in config.classes[class_name].checks
            }
            full_override = f"full run: unplaced file {unrelated}"
            default_reason = "full run" if mode is None else None
            for case, changed, facts, expected_reasons, full in (
                ("changed", {initializer}, graph, reasons, default_reason),
                ("clean", set(), graph, {}, default_reason),
                ("full override", {initializer, unrelated}, incomplete_graph, reasons, full_override),
            ):
                with self.subTest(adapter=name, check=check.id, case=case):
                    runner.reset_mock()
                    result = self.run_selection(config, check, classes, changed, facts)
                    selected = (
                        dict.fromkeys(inputs, full) if full else
                        {path: expected_reasons[path] for path in inputs & expected_reasons.keys()}
                    )
                    left_out = dict.fromkeys(inputs - selected.keys(), checks.OUTSIDE_SCOPE)
                    reason = full or ("affected files" if selected else checks.OUTSIDE_SCOPE)
                    report = result.to_json()["selection"]
                    self.assertDictEqual(report["selected"], selected, f"{check.id} selected inputs")
                    self.assertDictEqual(report["left_out"], left_out, f"{check.id} left-out inputs")
                    self.assertEqual(report["reason"], reason, check.id)
                    if selected:
                        runner.assert_called_once()
                        context = runner.call_args.args[0]
                        self.assertEqual(context.files, sorted(selected), check.id)
                        self.assertCountEqual(context.inventory_files, classes, check.id)
                    else:
                        runner.assert_not_called()
                        self.assertEqual(result.execution, "not_run", check.id)

    def test_selection_evidence_uses_the_scheduler_report(self):
        descriptor = dataclasses.replace(STUB, file_selection="affected", run=self.run_selection_stub)
        classes = {"a.py": "python", "b.py": "python"}
        graph = (set(classes), {"a.py": "changed"}, {"a.py": "changed"})
        with mock.patch.dict(adapters.ADAPTERS, {STUB.name: descriptor}):
            config = self.config(STUB_CONFIG)
            result = self.run_selection(config, config.checks["stub"], classes, {"a.py"}, graph)
        selection = result.to_json()["selection"]
        evidence = gate_result._ledger_check(result)["selection"]
        self.assertEqual(evidence, {key: list(selection[key]) for key in ("selected", "left_out")})
        self.assertEqual(evidence, {"selected": ["a.py"], "left_out": ["b.py"]})
        self.assertNotIn("reason", evidence)

    def run_selection(self, config, check, classes, changed, graph):
        diff = DiffBaseOverride(changed_paths=None if changed is None else frozenset(changed))
        with (
            tempfile.TemporaryDirectory(dir=self.root) as directory,
            mock.patch.object(checks, "affected_graph", return_value=graph),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            return checks._policy_results(
                self.root, config, sorted(classes), classes, 0, [check], diff, Path(directory), False,
            )[0]

    @staticmethod
    def run_selection_stub(context: adapters.AdapterContext) -> checks.CheckResult:
        assert context.selection is not None
        context.selection.selected.clear()
        context.selection.left_out["injected.py"] = "adapter reason"
        result = run_stub(context)
        result.report_fields["selection"] = {"reason": "adapter report"}
        return result

    def test_parsed_command_selection_uses_only_an_exact_files_argument(self) -> None:
        import json

        for argument, suite, mode in (
            ("{files}", False, "affected"),
            ("prefix={files}", False, None),
            ("{files}\n", False, None),
            ("{files}", True, None),
        ):
            with self.subTest(argument=argument, suite=suite):
                run = json.dumps([sys.executable, "-c", "print('Ran 1 test')", argument])
                config_text = STUB_CONFIG.replace('adapter = "stub"', 'adapter = "command"')
                config_text = config_text.replace("count = 4", f"run = {run}")
                if suite:
                    config_text += "\ntests_pattern = 'Ran ([0-9]+) test'\n"
                config = self.config(config_text)
                check = config.checks["stub"]
                self.assertEqual(checks._file_selection_mode(check), mode, check.id)
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    result = checks.run_check(
                        self.root, config, check, ["a.py"], {"a.py": "python"},
                        prefix="check: stub", evidence_dir=self.root,
                    )
                    empty = checks.run_check(
                        self.root, config, check, [], {}, prefix="check: stub", evidence_dir=self.root,
                    )
                self.assertEqual(result.outcome, "pass", result.reason)
                expected = "a.py" if argument == "{files}" else argument
                self.assertEqual(result.diagnostics.argv[-1], expected)
                if argument == "{files}":
                    self.assertIn("no files selected", empty.reason)
                else:
                    self.assertEqual(empty.outcome, "pass", empty.reason)

    def test_coverage_suites_are_scheduled_by_runtime_and_dependencies(self) -> None:
        descriptor = dataclasses.replace(
            STUB, name="coverage-bridge", keys=("requires",), parse=parse_coverage_bridge,
        )
        adapters.register_adapter(descriptor)
        self.addCleanup(adapters.remove_adapter, descriptor.name)
        (self.root / "suite.el").touch()
        config = self.config(COVERAGE_CONFIG)
        measures = [check for check in config.checks.values() if "crap" in check.evidence]
        for case, changed, targets, should_run in (
            ("changed", {"a.py"}, measures, True),
            ("clean", set(), measures, False),
            ("forced", set(), [config.checks["verify"]], True),
        ):
            with self.subTest(case=case):
                scheduled = [config.checks[name] for name in checks._needed_order(config, targets)]
                graph = ({"a.py"}, {"a.py": "changed"}, {"a.py": "changed"})
                with (
                    mock.patch.object(checks, "affected_graph", return_value=graph),
                    mock.patch.object(checks, "_require_coverage", create=True,
                                      side_effect=AssertionError("planner invoked coverage repair")),
                ):
                    plan = checks._affected_selection(
                        self.root, config, ["a.py"], {"a.py": "python"}, self.root,
                        frozenset(changed), scheduled, None,
                    )
                running = {name for name, selection in plan.items() if not selection.skip}
                for measure in measures:
                    self.assertEqual(measure.id in running, should_run, measure.id)
                    if measure.id in running:
                        missing = set(measure.required) - running
                        self.assertFalse(
                            missing, f"{measure.id} is missing required suites {sorted(missing)}",
                        )
                if case == "forced":
                    for measure in measures:
                        for suite in measure.required:
                            self.assertEqual(plan[suite].reason, "full run: required by verify", suite)

    def test_stub_is_parsed_run_and_displayed_through_the_registry(self) -> None:
        config = self.config(STUB_CONFIG)
        check = config.checks["stub"]
        self.assertEqual(check.spec, StubSpec(4))
        self.assertEqual(check.threshold, 0)

        result = checks.run_check(
            self.root,
            config,
            check,
            ["a.py"],
            {"a.py": "python"},
            prefix="check: stub",
            evidence_dir=self.root,
        )
        self.assertEqual(result.outcome, "pass")
        self.assertEqual((result.tests_ran, result.tests_skipped), (4, 0))
        self.assertEqual(ratchet._display_number(2.5, "stub"), "2.50")

    def test_verification_uses_every_adapter_that_produces_tests(self) -> None:
        (self.root / "verification.toml").write_text(
            baseline_text(
                [{
                    "subject": "tests:stub:executed",
                    "bound": 4,
                    "reason": "stub floor",
                }],
                check="verification",
                metric_version="verification/1",
            ),
            encoding="utf-8",
        )
        config = self.config(VERIFICATION_CONFIG)
        files = ["a.py"]
        classes = {"a.py": "python"}
        stub = checks.run_check(
            self.root, config, config.checks["stub"], files, classes,
            prefix="check: stub", evidence_dir=self.root,
        )
        verification = checks.run_check(
            self.root, config, config.checks["verification"], files, classes,
            prefix="check: verification", evidence_dir=self.root, prior={"stub": stub},
        )
        self.assertEqual(verification.outcome, "pass", verification.reason)
        self.assertTrue(verification.is_satisfied())
        self.assertIn(
            "tests:stub:executed",
            [finding.subject for finding in verification.findings],
        )

    def test_built_in_adapter_without_a_baseline_accepts_no_entries(self) -> None:
        text = with_clones().replace(
            'baseline = "quality-gate-clones.toml"\n', ""
        )
        config = self.config(text)
        check = config.checks["clones"]
        self.assertIsNone(check.baseline)
        self.assertEqual(checks._baseline_entries(check), [])

    def test_built_in_adapter_with_an_existing_baseline_loads_it(self) -> None:
        (self.root / "quality-gate-clones.toml").write_text(
            baseline_text(
                [{"subject": "fp1", "bound": 1, "reason": "reviewed"}]
            ),
            encoding="utf-8",
        )
        config = self.config(with_clones())
        entries = checks._baseline_entries(config.checks["clones"])
        self.assertEqual(
            [(entry.subject, entry.bound, entry.reason) for entry in entries],
            [("fp1", 1, "reviewed")],
        )

    def test_any_adapter_can_report_its_tool_identity(self) -> None:
        config = self.config(STUB_CONFIG)
        result = run_stub(adapters.AdapterContext(
            self.root, config, config.checks["stub"], [], {}, "stub", {},
            self.root / "evidence", inventory_files=[],
        ))
        self.assertNotIn("tool", result.to_json())
        result.tool = {"name": "fixture compiler", "version": "2.3"}
        document = result.to_json()
        self.assertEqual(document["tool"], result.tool)
        self.assertNotIn("emacs_version", document)

    def test_subject_labels_come_from_the_descriptor(self) -> None:
        for noun, existing, new in (
            ("", "existing", "added"),
            ("widget", "widget existing", "new widget added"),
        ):
            descriptor = dataclasses.replace(STUB, name=f"subject-{noun or 'empty'}", subject_noun=noun)
            adapters.register_adapter(descriptor)
            self.addCleanup(adapters.remove_adapter, descriptor.name)
            for adapter in (descriptor, descriptor.name):
                with self.subTest(noun=noun, adapter=adapter):
                    errors = io.StringIO()
                    with contextlib.redirect_stderr(errors):
                        result = ratchet.evaluate(
                            [
                                ratchet.Finding("existing", 2, "file:1"),
                                ratchet.Finding("added", 2, "file:2"),
                            ],
                            [ratchet.BaselineEntry("existing", 1, "accepted")],
                            threshold=0, enforcement="enforced", prefix="check: stub",
                            adapter=adapter, domain=ratchet.Domain.all(),
                        )
                    self.assertFalse(result.satisfied)
                    self.assertEqual(
                        errors.getvalue(),
                        f"check: stub: {existing}: value 2.00 exceeds threshold 0.00"
                        " and baseline bound 1.00 at file:1\n"
                        f"check: stub: {new}: value 2.00 exceeds threshold 0.00"
                        " at file:2\n",
                    )

    def test_findings_use_the_same_subject_direction_as_baseline_entries(self) -> None:
        entry = ratchet.BaselineEntry("tests:tests:executed", 4, "floor")
        finding = ratchet.Finding(
            "tests:tests:executed", 5, "test summary", kind="metric"
        )
        result = ratchet.evaluate(
            [finding],
            [entry],
            threshold=0,
            enforcement="enforced",
            prefix="check: verification",
            adapter="verification",
            domain=ratchet.Domain.all(),
        )
        self.assertEqual(result.entries[0].direction, "min")
        self.assertEqual(result.findings[0].direction, "min")
        self.assertFalse(result.findings[0].blocking)

        finding = ratchet.Finding(
            "not-a-test-subject", 5, "test summary", kind="executed"
        )
        result = ratchet.evaluate(
            [finding],
            [ratchet.BaselineEntry("not-a-test-subject", 4, "floor")],
            threshold=0,
            enforcement="enforced",
            prefix="check: verification",
            adapter="verification",
            domain=ratchet.Domain.all(),
        )
        self.assertEqual(result.entries[0].direction, "max")
        self.assertEqual(result.findings[0].direction, "max")
        self.assertTrue(result.findings[0].blocking)

    def test_descriptor_subject_rule_covers_floor_kind(self) -> None:
        entry = ratchet.BaselineEntry("floor-subject", 4, "floor")
        result = ratchet.evaluate(
            [ratchet.Finding("floor-subject", 5, "file:1", kind="floor")],
            [entry],
            threshold=0,
            enforcement="enforced",
            prefix="check: stub",
            adapter=STUB,
            domain=ratchet.Domain.all(),
        )
        self.assertEqual(result.findings[0].direction, "min")
        self.assertFalse(result.findings[0].blocking)

    def test_fixed_descriptor_default_drives_loading_and_evaluation(self) -> None:
        descriptor = dataclasses.replace(
            FLOOR_STUB, default_direction="min", entry_direction=None,
        )
        adapters.register_adapter(descriptor)
        self.addCleanup(adapters.remove_adapter, descriptor.name)
        path = self.root / "floor.toml"
        path.write_text(
            baseline_text(
                [{"subject": "anything", "bound": 4, "reason": "floor"}],
                check="floor", metric_version="stub/1",
            ),
            encoding="utf-8",
        )
        entries = ratchet.load_baseline(
            path, check_id="floor", metric_version="stub/1",
            adapter=descriptor, direction="max",
        )
        self.assertEqual(entries[0].direction, "min")
        result = ratchet.evaluate(
            [ratchet.Finding("anything", 3, "file:1")], entries,
            threshold=0, enforcement="enforced", prefix="check: floor",
            adapter=descriptor, domain=ratchet.Domain.all(), direction="max",
        )
        self.assertEqual(result.entries[0].direction, "min")
        self.assertEqual(result.findings[0].direction, "min")
        self.assertFalse(result.satisfied)

    def test_finding_without_entry_uses_the_subject_rule(self) -> None:
        result = ratchet.evaluate(
            [ratchet.Finding("floor-subject", 5, "file:1", kind="metric")], [],
            threshold=0, enforcement="enforced", prefix="check: stub",
            adapter=STUB, domain=ratchet.Domain.all(), direction="max",
        )
        self.assertEqual(result.findings[0].direction, "min")
        self.assertEqual(result.unmeasured, ["floor-subject"])
        self.assertFalse(result.satisfied)

    def test_prune_keeps_a_minimum_metric_at_its_measured_value(self) -> None:
        result = ratchet.evaluate(
            [ratchet.Finding("floor-subject", 5, "file:1", kind="floor")],
            [ratchet.BaselineEntry("floor-subject", 4, "floor")],
            threshold=0,
            enforcement="enforced",
            prefix="check: stub",
            adapter=STUB,
            domain=ratchet.Domain.all(),
        )
        self.assertEqual(result.findings[0].direction, "min")
        self.assertTrue(result.findings[0].covered_by_baseline)
        self.assertEqual(
            [entry.bound for entry in ratchet.pruned_entries(result)], [5]
        )


if __name__ == "__main__":
    unittest.main()
