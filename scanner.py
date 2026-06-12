import re
import base64
import requests
from dataclasses import dataclass, field
from typing import Optional

GITHUB_API = "https://api.github.com"

SECRET_PATTERNS = [
    (r"(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*['\"]?([A-Za-z0-9/+=]{16,})", "AWS credential"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)(razorpay_key|rzp_live|rzp_test)[_\s]*[=:]\s*['\"]?([a-zA-Z0-9_]{20,})", "Razorpay key"),
    (r"sk-[a-zA-Z0-9]{32,}", "OpenAI API key"),
    (r"(?i)(api_key|apikey|api_secret)\s*[=:]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]", "Generic API key"),
    (r"(?i)(password|passwd|pwd)\s*=\s*['\"]([^'\"]{6,})['\"]", "Hardcoded password"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"(?i)(secret_key|django_secret|flask_secret)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "Framework secret key"),
    (r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----", "Private key"),
    (r"(?i)(database_url)\s*=\s*['\"]?(postgres|mysql|mongodb)://[^\s'\"]+", "Database URL with credentials"),
]

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".env", ".yml", ".yaml", ".json",
                   ".txt", ".cfg", ".ini", ".sh", ".bash", ".rb", ".php",
                   ".go", ".rs", ".java", ".xml", ".toml", ".conf"}

RISKY_FILES = {
    ".env": "Live .env file committed — may contain real secrets",
    ".env.local": ".env.local committed — check for real credentials",
    "id_rsa": "Private SSH key in repository",
    "id_ed25519": "Private SSH key in repository",
    "credentials.json": "Credentials file committed",
    "serviceAccountKey.json": "Firebase service account key",
}

DEP_FILES = {
    "requirements.txt": "PyPI",
    "Pipfile": "PyPI",
    "package.json": "npm",
    "pom.xml": "Maven",
    "Gemfile": "RubyGems",
    "go.mod": "Go",
}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    file: str = ""
    line: int = 0


@dataclass
class ScanResult:
    owner: str
    repo: str
    description: str
    language: str
    stars: int
    findings: list = field(default_factory=list)
    dep_ecosystems: list = field(default_factory=list)
    score: int = 100
    error: str = ""


def _headers(token=None):
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _get(url, token=None):
    try:
        r = requests.get(url, headers=_headers(token), timeout=15)
        if r.status_code != 200:
            return None
        ct = r.headers.get("content-type", "")
        if "json" not in ct:
            return None
        return r.json()
    except Exception:
        return None


def _decode_content(data):
    try:
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    except Exception:
        return None


def scan_repo(owner, repo, token=None):
    result = ScanResult(owner=owner, repo=repo, description="", language="", stars=0)

    meta = _get(f"{GITHUB_API}/repos/{owner}/{repo}", token)
    if not meta or not isinstance(meta, dict):
        result.error = "Repository not found or GitHub API rate limit hit. Add a GitHub token."
        return result

    result.description = meta.get("description") or ""
    result.language = meta.get("language") or "Unknown"
    result.stars = meta.get("stargazers_count", 0)

    if meta.get("private"):
        result.error = "Private repository — cannot scan without user OAuth."
        return result

    # File tree
    tree_data = _get(f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/HEAD?recursive=1", token)
    if not tree_data or not isinstance(tree_data, dict):
        # fallback to contents API
        tree_data = _get(f"{GITHUB_API}/repos/{owner}/{repo}/contents/", token)
        if not tree_data:
            result.error = "Could not fetch file tree."
            return result
        all_files = [item["path"] for item in tree_data if isinstance(item, dict) and item.get("type") == "file"]
    else:
        all_files = [item["path"] for item in tree_data.get("tree", []) if item.get("type") == "blob"]

    # Misconfig check
    for path in all_files:
        filename = path.split("/")[-1]
        for risky, msg in RISKY_FILES.items():
            if filename == risky:
                severity = "critical" if risky in (".env", "id_rsa", "id_ed25519", "serviceAccountKey.json") else "high"
                result.findings.append(Finding(severity, "misconfig", f"Sensitive file committed: {filename}", msg, path))
                result.score -= 15 if severity == "critical" else 10

    # Secret scan
    scannable = [p for p in all_files if any(p.endswith(ext) for ext in SCAN_EXTENSIONS)
                 or p.split("/")[-1].startswith(".env")]
    scannable = scannable[:25]

    for path in scannable:
        content_data = _get(f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}", token)
        if not content_data or not isinstance(content_data, dict):
            continue
        content = _decode_content(content_data)
        if not content:
            continue
        for pattern, label in SECRET_PATTERNS:
            for m in re.finditer(pattern, content):
                line_no = content[:m.start()].count("\n") + 1
                result.findings.append(Finding(
                    "critical", "secrets", f"{label} found",
                    f"Pattern matched in `{path}` at line {line_no}. Rotate immediately.",
                    path, line_no
                ))
                result.score -= 20

    # Dependency detection
    for dep_file, ecosystem in DEP_FILES.items():
        if any(p.endswith(dep_file) for p in all_files):
            result.dep_ecosystems.append(ecosystem)

    # Commit hygiene
    commits = _get(f"{GITHUB_API}/repos/{owner}/{repo}/commits?per_page=20", token)
    if commits and isinstance(commits, list):
        secret_keywords = ["remove secret", "delete key", "fix credential", "remove password",
                           "remove api key", "remove token", "revoke", "accidental"]
        for c in commits:
            msg = c.get("commit", {}).get("message", "").lower()
            if any(kw in msg for kw in secret_keywords):
                result.findings.append(Finding(
                    "high", "hygiene", "Possible past secret leak",
                    f"Commit suggests a secret was pushed then removed: '{msg[:100]}'. May still exist in history.",
                ))
                result.score -= 12
                break

    # README check
    readme_data = _get(f"{GITHUB_API}/repos/{owner}/{repo}/readme", token)
    if readme_data and isinstance(readme_data, dict):
        readme = _decode_content(readme_data)
        if readme:
            for pattern, label in SECRET_PATTERNS[:5]:
                if re.search(pattern, readme):
                    result.findings.append(Finding(
                        "critical", "secrets", f"{label} in README",
                        "Credentials found in README.md — visible to everyone. Rotate immediately.",
                        "README.md"
                    ))
                    result.score -= 25

    result.score = max(0, min(100, result.score))

    if not result.findings:
        result.findings.append(Finding(
            "info", "hygiene", "No obvious issues found",
            "Surface scan found no hardcoded secrets, risky files, or suspicious commits. "
            "This is not a full pentest — always do manual review for critical projects."
        ))

    return result
