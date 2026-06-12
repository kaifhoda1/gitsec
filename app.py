import os
from flask import Flask, render_template, request, jsonify, redirect
from scanner import scan_repo, ScanResult
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")


def result_to_dict(r: ScanResult) -> dict:
    return {
        "owner": r.owner,
        "repo": r.repo,
        "description": r.description,
        "language": r.language,
        "stars": r.stars,
        "score": r.score,
        "error": r.error,
        "dep_ecosystems": r.dep_ecosystems,
        "findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "detail": f.detail,
                "file": f.file,
                "line": f.line,
            }
            for f in r.findings
        ],
    }


@app.route("/")
def index():
    return render_template("index.html")


# URL-swap trick: gitsec.dev/owner/repo  OR  gitsec.dev/owner/repo/tree/...
@app.route("/<owner>/<repo>")
@app.route("/<owner>/<repo>/tree/<path:branch>")
def scan_page(owner, repo, branch=None):
    return render_template("result.html", owner=owner, repo=repo)


@app.route("/api/scan/<owner>/<repo>")
def api_scan(owner, repo):
    result = scan_repo(owner, repo, GITHUB_TOKEN or None)
    return jsonify(result_to_dict(result))


if __name__ == "__main__":
    app.run(debug=True, port=5050)
