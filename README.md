# GitSec — Instant GitHub Security Audit

> Replace `github.com` with `your-domain.com` in any GitHub URL for an instant security report.

![Python](https://img.shields.io/badge/Python-3.10+-blue) ![Flask](https://img.shields.io/badge/Flask-3.0-green) ![License](https://img.shields.io/badge/License-MIT-yellow)

---

## What is GitSec?

GitSec is an open-source security audit tool for public GitHub repositories. It scans any repo in seconds and gives you a risk score with detailed findings — no setup, no account needed.

**The URL trick:**
```
github.com/django/django → your-domain.com/django/django
```
Just swap the domain and hit enter.

---

## What it scans

| Check | What it looks for |
|---|---|
| Secrets | API keys, tokens, passwords hardcoded in source files |
| ️ Misconfigurations | `.env` files committed, private keys, credential files |
| Dependencies | Detects package ecosystems (PyPI, npm, Maven, Go) |
| Commit hygiene | Suspicious commit messages suggesting past secret leaks |
| README scan | Credentials accidentally left in documentation |

**Supported secret patterns:**
- AWS Access Keys and Secret Keys
- Razorpay API keys (rzp_live, rzp_test)
- OpenAI API keys (sk-...)
- GitHub Personal Access Tokens (ghp_...)
- Private SSH keys (RSA, EC, OpenSSH)
- Django / Flask secret keys
- Database URLs with embedded credentials
- Generic API keys and hardcoded passwords

---

## Risk Score

Every scan produces a score from 0 to 100.

| Score | Risk Level |
|---|---|
| 80 – 100 | Low Risk |
| 60 – 79 | Moderate Risk |
| 40 – 59 | High Risk |
| 0 – 39 | Critical Risk |

---

## Screenshots

**Homepage**

Clean search interface. Type any GitHub repo and hit Scan.

**Result page**

Score ring, severity counts, and detailed findings with file paths and line numbers.

---

## Run locally

**Requirements:**
- Python 3.10+
- pip

**Steps:**

```bash
# 1. Clone the repo
git clone https://github.com/kaifhoda1/gitsec.git
cd gitsec

# 2. Install dependencies
pip install -r requirements.txt

# 3. Add GitHub token (recommended)
cp .env.example .env
# Open .env and paste your GitHub token
# Get one free at: github.com/settings/tokens (no scopes needed)

# 4. Run
python3 app.py
```

Open `http://localhost:5050` in your browser.

**Without a GitHub token:** Works but limited to 60 API requests per hour. 
**With a GitHub token:** 5000 requests per hour. Get one free at [github.com/settings/tokens](https://github.com/settings/tokens) — no scopes needed.

---

## Deploy your own instance

Works on any Python hosting platform.

**Render.com (free tier):**
1. Fork this repo
2. Connect to [render.com](https://render.com)
3. New Web Service → connect your fork
4. Build command: `pip install -r requirements.txt`
5. Start command: `python3 app.py`
6. Add environment variable: `GITHUB_TOKEN=your_token`
7. Deploy

**Railway / Fly.io / VPS:** Same steps, set `GITHUB_TOKEN` as environment variable.

---

## Project structure

```
gitsec/
├── app.py # Flask server and URL routing
├── scanner.py # Core scanning logic
├── requirements.txt # Python dependencies
├── .env.example # Environment variable template
└── templates/
 ├── index.html # Homepage
 └── result.html # Scan results page
```

---

## How it works

1. User enters a GitHub repo URL
2. App calls GitHub REST API to fetch repo metadata, file tree, and file contents
3. Scanner runs regex patterns against file contents to detect secrets
4. Checks file names against a list of known risky files (.env, id_rsa, etc.)
5. Scans recent commit messages for signs of past credential leaks
6. Calculates a risk score and returns structured findings
7. Results render in the browser with severity levels and file locations

---

## Limitations

- Scans **public repositories only**
- Surface-level scan — not a replacement for a full security audit or pentest
- Scans up to 25 files per repo to stay within GitHub API rate limits
- Does not scan full git history (only recent commits)
- False positives possible — example keys in documentation may be flagged

---

## Roadmap

- [ ] CVE scanning via OSV.dev API for detected dependencies
- [ ] Full git history scanning for deleted secrets
- [ ] Badge system — embed a GitSec score badge in your README
- [ ] CLI version — `gitsec owner/repo` from terminal
- [ ] GitHub Action — run on every pull request

---

## Contributing

Pull requests welcome. Open an issue first for major changes.

---

## License

MIT License — free to use, modify, and distribute.

---

## Built by

**ByteFortix Security** — Cybersecurity tools and GRC consulting. 
GitHub: [@kaifhoda1](https://github.com/kaifhoda1)
