# Security Architecture Notes

This document describes the security decisions made in `src/research_agent.py` and the rationale behind them. It is intended for maintainers, security reviewers, and operators deploying this service.

---

## 1. Secret Management

**Principle:** No secrets in source code or environment defaults.

- `ANTHROPIC_API_KEY`, `BRAVE_API_KEY`, and `FLASK_SECRET_KEY` are read exclusively from environment variables at startup.
- If any required key is missing, the application exits with a clear error message rather than falling back to an insecure default.
- API keys are passed in HTTP **headers**, not query parameters, to avoid appearing in server access logs.
- Keys are never logged, echoed in error messages, or serialised to disk.

**Operator action:** Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler) in production rather than a plaintext `.env` file.

---

## 2. Input Validation

**Principle:** All external input is validated before use.

| Input | Validation applied |
|---|---|
| Research question (UI / CLI) | Length-capped, null-byte stripped, type-checked |
| Export formats | Whitelist: only `{md, pdf, docx}` accepted |
| Session ID (SSE endpoint) | Regex-checked: `[0-9a-f]{16}` only |
| Download path | Resolved and confined to `REPORTS_DIR` |
| Host header | Validated against `ALLOWED_HOSTS` |
| SQL column names | Checked against a hard-coded allowlist before use in `UPDATE` |

**Residual risk:** The research question is forwarded to the Claude API. Adversarial prompts in the question may attempt to alter agent behaviour (prompt injection). The length cap and absence of system-prompt injection reduce but do not eliminate this risk.

---

## 3. SQL Injection Prevention

All database operations use **parameterised queries** (`?` placeholders via the `sqlite3` module). No SQL is ever constructed by string concatenation with user-supplied values.

The `session_update` function validates column names against a hard-coded set before constructing the `SET` clause, preventing an attacker who could call internal functions from injecting column names.

---

## 4. Path Traversal Prevention

The `/download` endpoint resolves the requested path with `Path.resolve()` and calls `.relative_to(REPORTS_DIR)` to confirm the resolved path is a strict child of the reports directory. Any path containing `..`, symlinks to other directories, or absolute escapes is rejected with a 404.

Cache filenames are derived from SHA-256 hashes of the cache key, never from raw user input, so they cannot contain path separators or shell metacharacters.

---

## 5. HTTP Security Headers

The `@app.after_request` hook injects the following headers on every response:

| Header | Value | Purpose |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-sniffing |
| `X-Frame-Options` | `DENY` | Prevents clickjacking |
| `X-XSS-Protection` | `1; mode=block` | Legacy browser XSS filter |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limits referrer leakage |
| `Content-Security-Policy` | Restrictive default-src | Mitigates XSS |

**HSTS** (`Strict-Transport-Security`) is present in the code but commented out. Enable it when TLS is terminated at this process. If TLS is terminated at a reverse proxy, set HSTS there instead.

---

## 6. XSS Prevention in the Web UI

The frontend JavaScript uses **`textContent`** (not `innerHTML`) for all dynamic content derived from server responses. The single exception is the static HTML template itself, which is authored by maintainers and not influenced by user input.

The `Content-Security-Policy` header further restricts script execution to same-origin sources.

---

## 7. Flask Configuration

- `debug=False` is hard-coded in the `create_app` call. The Werkzeug debugger, when enabled, exposes an interactive Python REPL to anyone who can trigger a 500 error — this is a critical RCE vulnerability in production.
- `app.secret_key` is set from `FLASK_SECRET_KEY`. If this is absent, the app raises at startup rather than using a weak default.
- The bind address defaults to `127.0.0.1` (loopback only). Operators must explicitly pass `--host 0.0.0.0` to expose on all interfaces, and should then place a TLS-terminating reverse proxy in front.

---

## 8. Outbound HTTP

- **TLS verification is always enabled.** `requests.get()` calls never pass `verify=False`.
- Requests have explicit timeouts (12 s for search, 18 s for page fetch) to prevent indefinite hangs.
- The User-Agent string identifies this software honestly; browser impersonation is avoided.
- Redirects are followed (`allow_redirects=True`) but requests does not follow cross-scheme redirects (http → https is fine; https → http is blocked by default TLS validation).

---

## 9. Concurrency and Thread Safety

- The SQLite connection uses a threading lock (`_db_lock`) to serialise writes, avoiding database corruption from concurrent agent runs.
- `CitationTracker` uses its own lock for thread-safe registration.
- SSE queues are per-session and accessed only by the owning worker thread (write) and the SSE generator (read), which is safe for `queue.Queue`.

---

## 10. Dependency Security

- All dependencies are pinned to specific versions in `requirements.txt` with a `requirements.lock` (generated by `pip-compile`).
- No dependencies are used for cryptography, authentication, or TLS; these are handled by the stdlib and `requests`/`anthropic` respectively.
- Run `pip-audit` or `safety check` in CI to detect known CVEs.

---

## 11. Data Retention

- Reports are written to disk and retained indefinitely. Operators should implement a retention policy (e.g., a cron job that deletes files older than N days).
- The SQLite session store contains research questions. If questions may contain PII, encrypt the database at rest or use an encrypted volume.
- Cache entries expire after `CACHE_TTL_SECONDS` (default 24 h) but are not deleted proactively; a periodic `find cache/ -mtime +1 -delete` cron entry is recommended.

---

*Last updated: April 2025*
