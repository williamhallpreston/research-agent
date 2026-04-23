# Contributing to Research Agent

Thank you for your interest in contributing! This document explains the process for submitting changes.

---

## Getting Started

1. **Fork** the repository and clone your fork.
2. Create a **feature branch**: `git checkout -b feat/my-feature`
3. Set up your environment:
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements-dev.txt
   cp .env.example .env   # fill in test credentials
   ```
4. Make your changes, including tests and docstrings.
5. Run checks:
   ```bash
   pytest tests/ -v --cov=src
   ruff check src/ tests/
   mypy src/
   pip-audit
   ```
6. Commit with a clear message, then open a **Pull Request** against `main`.

---

## Code Standards

- **Style:** PEP 8, enforced by `ruff`.
- **Type hints:** All public functions must have type annotations.
- **Docstrings:** Google-style for all public functions and classes.
- **Security:** Add a `# SECURITY:` comment for any code that handles auth, crypto, input parsing, or privilege changes.
- **Tests:** All new code requires at least one unit test. Security-sensitive paths require both a happy-path test and a test of the rejection case.
- **No secrets:** Never commit real API keys, tokens, or credentials — even in tests.

---

## Security Contributions

If your change touches authentication, input validation, file I/O, or HTTP handling, please also:
- Update `docs/SECURITY_NOTES.md` to reflect the change.
- Add or update a corresponding test in `tests/test_agent.py`.

For vulnerabilities, follow the responsible disclosure process in [`SECURITY.md`](SECURITY.md) rather than opening a public issue.

---

## Pull Request Checklist

- [ ] Tests pass (`pytest`)
- [ ] No new linting errors (`ruff check`)
- [ ] Type checks pass (`mypy src/`)
- [ ] No known CVEs in new dependencies (`pip-audit`)
- [ ] No secrets or credentials in the diff
- [ ] `SECURITY_NOTES.md` updated if security-relevant
- [ ] `CHANGELOG.md` entry added (if applicable)
