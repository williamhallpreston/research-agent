# 🔬 Research Agent

An autonomous research agent powered by [Claude](https://www.anthropic.com/claude) that takes a question, searches the web, reads and evaluates sources, and produces structured, cited reports — with a live-streaming web UI and CLI.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-SECURITY.md-orange)](SECURITY.md)

---

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [Code of Conduct](#code-of-conduct)
- [License](#license)

---

## Features

| Feature | Details |
|---|---|
| **Agentic loop** | Claude drives multi-step planning → search → read → synthesize → self-review |
| **Web UI** | Flask server with live Server-Sent Event streaming |
| **Session memory** | SQLite-backed; every run persisted with full message history |
| **Export formats** | Markdown, PDF (reportlab), DOCX (python-docx) — all three in one run |
| **Credibility scoring** | 1–5 ★ per source, scored by domain pattern |
| **Citation tracking** | Deduplicated `[^N]` IDs inline + full reference list |
| **Resilience** | Exponential-backoff retry, TTL-aware SHA-256 disk cache |
| **Security-hardened** | Input validation, path-traversal guards, HTTP security headers, no debug mode |

---

## Tech Stack

| Layer | Library |
|---|---|
| LLM | [anthropic](https://pypi.org/project/anthropic/) (`claude-opus-4-5`) |
| Web search | [Brave Search API](https://brave.com/search/api/) |
| Web UI | [Flask](https://flask.palletsprojects.com/) 3.x |
| PDF export | [reportlab](https://www.reportlab.com/) |
| DOCX export | [python-docx](https://python-docx.readthedocs.io/) |
| Persistence | SQLite (stdlib) |
| HTTP client | [requests](https://requests.readthedocs.io/) |

Requires **Python 3.11+**.

---

## Project Structure

```
research-agent/
├── src/
│   └── research_agent.py       # Main agent, tools, exporters, Flask UI
├── tests/
│   └── test_agent.py           # Unit tests (pytest)
├── docs/
│   └── SECURITY_NOTES.md       # In-depth security architecture notes
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── PULL_REQUEST_TEMPLATE.md
├── reports/                    # Generated reports (git-ignored)
├── cache/                      # Search/page cache (git-ignored)
├── .env.example                # Template — copy to .env and fill in values
├── .gitignore
├── requirements.txt            # Pinned production dependencies
├── requirements-dev.txt        # Pinned development/test dependencies
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE
├── README.md
└── SECURITY.md
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-org/research-agent.git
cd research-agent
```

### 2. Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate       # macOS / Linux
.venv\Scripts\activate          # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

```bash
cp .env.example .env
# Edit .env and fill in your API keys (see Configuration below)
```

> ⚠️ **Never commit `.env` to version control.**  
> It is excluded by `.gitignore`. See [Security Considerations](#security-considerations).

---

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env`:

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | ✅ | Your Anthropic API key |
| `BRAVE_API_KEY` | ✅ (for live search) | Brave Search API key |
| `FLASK_SECRET_KEY` | ✅ (web UI) | Random secret for Flask sessions — generate with `python -c "import secrets; print(secrets.token_hex(32))"` |
| `ALLOWED_HOSTS` | Web UI | Comma-separated hostnames the server accepts (default: `localhost,127.0.0.1`) |
| `REPORTS_DIR` | No | Output directory for reports (default: `./reports`) |
| `CACHE_DIR` | No | Cache directory (default: `./cache`) |
| `DB_PATH` | No | SQLite database path (default: `./sessions.db`) |
| `MAX_QUESTION_LEN` | No | Max question length in chars (default: `500`) |
| `CACHE_TTL_SECONDS` | No | Cache entry lifetime in seconds (default: `86400`) |

---

## Usage

### Web UI

```bash
python src/research_agent.py --serve
# Open http://localhost:5000
```

Type a question, select export formats, click **Research**.  
Logs stream live. Download links appear on completion.

### CLI

```bash
# All three formats
python src/research_agent.py "What are the latest breakthroughs in fusion energy?" \
    --format md,pdf,docx

# Markdown only
python src/research_agent.py "State of large language models in 2025" --format md

# Custom host/port for the web UI
python src/research_agent.py --serve --host 0.0.0.0 --port 8080
```

Reports are written to the `reports/` directory:

```
reports/
  report_fusion_energy_20250422_143012.md
  report_fusion_energy_20250422_143012.pdf
  report_fusion_energy_20250422_143012.docx
```

### Running Tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

---

## Security Considerations

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting and [`docs/SECURITY_NOTES.md`](docs/SECURITY_NOTES.md) for architecture details.

### Key points for operators

- **API keys** are read from environment variables only — never hardcoded.
- **TLS verification** is always enabled on outbound HTTP requests. Do not set `REQUESTS_CA_BUNDLE=""` or patch `verify=False`.
- **Path traversal** is blocked: the `/download` endpoint resolves all paths and confirms they reside inside `REPORTS_DIR`.
- **SQL injection** is prevented: all database queries use parameterised statements.
- **debug mode** is hard-coded to `False` in the Flask app. Enabling it exposes an interactive REPL to anyone with network access.
- **Host header injection** is mitigated by validating the `Host` header against `ALLOWED_HOSTS`.
- **Input length** is capped at 500 characters (configurable) to reduce prompt-injection surface area.
- The web UI is designed for **single-operator / trusted-network use**. It does not implement authentication. If exposing beyond localhost, place it behind an authenticated reverse proxy (nginx, Caddy, etc.) and enable TLS.

### Known limitations

- No authentication layer — add one if deploying to a shared or public network.
- The research question is passed to an external LLM API; do not use for sensitive or classified questions.
- Fetched page content is not rendered as HTML, mitigating XSS, but content from fetched pages is passed to the LLM and may influence its output.

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines, coding standards, and the pull request process.

In brief:
1. Fork the repo and create a feature branch.
2. Make your changes with tests and docstrings.
3. Run `pytest` and ensure all tests pass.
4. Open a pull request against `main`.

For security-related contributions, follow the responsible disclosure process in [`SECURITY.md`](SECURITY.md).

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).  
Please read it before participating.

---

## License

[MIT](LICENSE) © 2025 Your Organisation
