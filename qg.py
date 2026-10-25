#!/usr/bin/env python3
"""code-quality-gate: policy checks, inventory, hygiene, ratchet and tools.

Run as 'python3 -I qg.py [--repo DIR] COMMAND'.  DIR is the top level of
a git work tree and its configuration is 'quality-gate.toml'.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from quality_gate.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
