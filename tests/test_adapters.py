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

from quality_gate.files import DiffBaseOverride
from quality_gate.python_tests import _parse_python_tests
from quality_gate.runner import Diagnostics

sys.path.insert(0, str(GATE))
adapters = importlib.import_module("quality_gate.adapters")
checks = importlib.import_module("quality_gate.checks")
policy = importlib.import_module("quality_gate.policy")
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
