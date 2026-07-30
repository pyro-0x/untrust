# Contributing to untrust

Thank you for your interest in contributing to `untrust`.

## Adding a new check

Each check is a Python module in `untrust/checks/` that:

1. Subclasses `Check` from `untrust.checks.base`
2. Implements a `run(target: Target) -> Finding` method
3. Returns a `Finding` with status, severity, summary, and remediation

### Template

```python
"""CHECK_ID: Short description.

Detailed explanation of what this check verifies and what exploitation
looks like if it fails.
"""
from __future__ import annotations

from .base import Check, Finding, Severity, Status, Target


class MyNewCheck(Check):
    check_id = "CATEGORY-NN"
    title = "Human-readable title"
    severity = Severity.MEDIUM

    def run(self, target: Target) -> Finding:
        # Your check logic here
        # Return a Finding with PASS, FAIL, SKIP, or ERROR
        ...
```

### Registration

Add your check class to `ALL_CHECKS` in `untrust/runner.py` and import it in `untrust/checks/__init__.py`.

## Development setup

```bash
git clone https://github.com/pyro-0x/untrust.git
cd untrust
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Code style

- Format with `ruff format`
- Lint with `ruff check`
- Type check with `mypy untrust/`

## Pull request guidelines

- One check per PR (unless they're tightly coupled)
- Include a test that exercises the check logic with mocked AWS responses
- Update the README table if adding a new check
- Reference any relevant CVEs, advisories, or research papers

## Reporting security issues

If you discover a security vulnerability in `untrust` itself, please report it privately via GitHub Security Advisories rather than opening a public issue.
