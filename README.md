# GitSec — Instant GitHub Security Audit

Replace `github.com` with `gitsec.dev` in any repo URL to get an instant security audit.

## What it scans

- **Secrets** — API keys, passwords, tokens hardcoded in source files and README
- **Misconfigurations** — `.env` files committed, private keys, credential files
- **Dependencies** — Detects dependency files (requirements.txt, package.json, etc.)
- **Commit hygiene** — Suspicious commit messages suggesting past secret leaks

## Run locally

```bash
# 1. Clone / copy this folder
cd gitsec

# 2. Install deps
pip install -r requirements.txt

# 3. Add GitHub token (recommended, raises rate limit to 5000/hr)
cp .env.example .env
# Edit .env and add your GitHub token

# 4. Run
python app.py
```

Open http://localhost:5050

## URL trick

Once deployed, replace `github.com` with your domain in any GitHub URL:

```
github.com/django/django  →  gitsec.dev/django/django
```

## Stack

- Python + Flask (backend)
- GitHub REST API (no auth needed for public repos)
- OSV.dev API for CVE lookups (dependency scanning)
- Vanilla HTML/CSS/JS (frontend — no build step)

## Deploy

Works on any Python host: Railway, Render, Fly.io, VPS.

Set `GITHUB_TOKEN` as an environment variable in production.

---

Built by [ByteFortix Security](https://bytefortix.com)
