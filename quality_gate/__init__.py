"""The code-quality-gate implementation package.

The core is standard-library Python. Policy loading and validation live in
policy.py; repository enumeration, inventory and hygiene in files.py; pinned
tool locks and installation in tools.py. The generic reasoned ratchet and its
baseline format live in ratchet.py. Adapters measure their subjects and the
core decides: clones.py owns jscpd evidence, python_tests.py and covrun.py run
tests under the pinned coverage wheel, coverage_tool.py loads and combines its
data, and python_crap.py joins coverage with ast complexity. checks.py runs the
adapters, gate_result.py computes identity and the decision, and cli.py holds
the command line. qg.py is only the entry point.
"""
