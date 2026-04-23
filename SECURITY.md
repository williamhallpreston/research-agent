# Security Policy

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability in this project, please **do not** open a public GitHub issue. Instead, follow the responsible disclosure process below.

### How to report

**Email:** security@your-org.example.com  
**PGP key:** Available at https://your-org.example.com/pgp-key.asc *(recommended for sensitive reports)*

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept code or screenshots where applicable)
- Any suggested mitigations you are aware of

### What to expect

| Step | Timeline |
|---|---|
| Acknowledgement of your report | Within **48 hours** |
| Confirmation of whether the issue is valid | Within **5 business days** |
| Status update and target resolution date | Within **10 business days** |
| Fix released (critical/high severity) | Within **30 days** where possible |
| Public disclosure | Coordinated with you after the fix is released |

We will credit you in the release notes (with your permission) and will not pursue legal action against good-faith security researchers.

---

## Supported Versions

| Version | Supported |
|---|---|
| `main` branch (latest) | ✅ Actively maintained |
| Older tagged releases | ❌ No security backports |

We recommend always running the latest commit on `main` or the most recent tagged release.

---

## Scope

The following are **in scope** for this policy:
- The `src/research_agent.py` application and its Flask web UI
- The SQLite session store and disk cache
- Dependency vulnerabilities that affect the runtime

The following are **out of scope**:
- Vulnerabilities in the Anthropic API or Brave Search API themselves
- Social-engineering attacks against maintainers
- Denial-of-service via intentionally slow research queries

---

## Security Design Principles

This project follows these principles. If you find a violation, that may be a reportable issue:

1. **No secrets in source code** — all credentials come from environment variables
2. **Parameterised SQL** — no string interpolation in database queries
3. **Path traversal prevention** — all file paths resolved and validated before access
4. **TLS always on** — no `verify=False` in outbound HTTP requests
5. **Whitelist input validation** — formats, session IDs, and host headers are validated before use
6. **debug=False** — Flask debug mode is never enabled at runtime
7. **Least privilege** — the process reads/writes only to explicitly configured directories

---

## Known Security Limitations

- **No authentication** on the web UI. It is designed for single-operator or trusted-network use. Operators should place it behind an authenticated reverse proxy with TLS if exposing beyond localhost.
- **Prompt injection** is a residual risk: adversarial content in fetched web pages could influence LLM behaviour. Mitigated by treating fetched content as data, not instructions.
- **Cache poisoning** is a theoretical risk if the cache directory is writable by untrusted processes. Ensure correct file-system permissions on the `cache/` directory.

---

*Last updated: April 2025*
