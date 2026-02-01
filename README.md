# Web Admin Honeypot (Python + Flask)

A lightweight web honeypot that mimics common admin portals (e.g., `/admin`, `/wp-login.php`, `/phpmyadmin`) to capture and classify malicious web traffic such as scanning, credential stuffing attempts, SQL injection, and path traversal.

## Features
- Decoy admin/login endpoints
- JSONL structured logging (`logs/events.jsonl`)
- Basic request classification: `common_scan`, `credential_attempt`, `sqli`, `xss`, `path_traversal`
- Credential hashing (no plaintext storage)
- Analysis script that generates a markdown report + charts

## Run locally
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
pip install flask pandas matplotlib
python honeypot/app.py

Open: http://localhost:8080/admin

## Generate report
python analysis.py


Outputs in reports/:
    summary.md
    hits_over_time.png
    CSV summaries

## Findings (Local Testing)
During local testing, the honeypot captured simulated attack traffic including:
- Common admin page scanning (`/wp-login.php`, `/phpmyadmin`)
- SQL injection attempts (`OR 1=1`)
- Path traversal attempts (`../../etc/passwd`)

Once deployed to a public cloud VM, the honeypot is expected to receive unsolicited traffic from automated scanners and bots within hours.