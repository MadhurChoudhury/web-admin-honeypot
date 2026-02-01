from flask import Flask, request, Response
from datetime import datetime, timezone
import json, os, hashlib

app = Flask(__name__)

LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "events.jsonl")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

# Simple in-memory rate limit (good enough for MVP)
# counts per IP per minute
ip_hits = {}

DECOY_PATHS = [
    "/", "/admin", "/login", "/wp-login.php", "/phpmyadmin", "/administrator", "/console"
]

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def client_ip():
    # If behind reverse proxy later, X-Forwarded-For may exist.
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

def log_event(event: dict):
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

def allowed(ip: str) -> bool:
    # max 60 hits/min per IP for MVP
    minute = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    key = f"{ip}:{minute}"
    ip_hits[key] = ip_hits.get(key, 0) + 1
    return ip_hits[key] <= 60

def decoy_page(title: str):
    html = f"""<!doctype html>
<html>
<head><title>{title}</title></head>
<body>
  <h2>{title}</h2>
  <form method="POST">
    <label>Username</label><br/>
    <input name="username" /><br/><br/>
    <label>Password</label><br/>
    <input name="password" type="password" /><br/><br/>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>"""
    return Response(html, mimetype="text/html")

def classify_request(path: str, body: str, qs: str) -> str:
    payload = (path + " " + qs + " " + body).lower()
    if any(x in payload for x in ["../", "..%2f", "%2e%2e%2f"]):
        return "path_traversal"
    if any(x in payload for x in [" union select", " or 1=1", "' or '1'='1", "sleep(", "benchmark("]):
        return "sqli"
    if any(x in payload for x in ["<script", "%3cscript", "onerror=", "onload="]):
        return "xss"
    if any(x in payload for x in ["wp-login.php", "xmlrpc.php", "phpmyadmin", "administrator", "/admin"]):
        return "common_scan"
    if request.method == "POST" and ("password" in payload or "passwd" in payload):
        return "credential_attempt"
    return "unknown"

@app.before_request
def capture():
    ip = client_ip()
    if not allowed(ip):
        # Still log that they were throttled
        log_event({
            "ts": now_iso(),
            "ip": ip,
            "method": request.method,
            "path": request.path,
            "status": 429,
            "note": "rate_limited"
        })
        return Response("Too Many Requests", status=429)

@app.route("/", methods=["GET"])
def home():
    return decoy_page("Welcome")

# Register multiple decoy endpoints
for p in DECOY_PATHS[1:]:
    def make_route(path):
        def handler():
            ip = client_ip()
            body = request.get_data(as_text=True)[:2000]  # limit size for safety
            qs = request.query_string.decode("utf-8", errors="ignore")[:1000]
            cls = classify_request(request.path, body, qs)

            # If credentials are sent, don't store plaintext; store hash for stats
            uname = request.form.get("username", "")
            pwd = request.form.get("password", "")
            cred_hash = ""
            if uname or pwd:
                cred_hash = sha256_text(f"{uname}:{pwd}")

            event = {
                "ts": now_iso(),
                "ip": ip,
                "method": request.method,
                "path": request.path,
                "query": qs,
                "user_agent": request.headers.get("User-Agent", ""),
                "referrer": request.headers.get("Referer", ""),
                "content_type": request.headers.get("Content-Type", ""),
                "body_sample": body[:400],  # store small sample only
                "classification": cls,
                "cred_hash": cred_hash,
            }
            log_event(event)

            # Always respond like a real site but never authenticate
            if request.method == "POST":
                return Response("Invalid username or password", status=401)
            return decoy_page(f"Admin Portal ({path})")
        handler.__name__ = f"handler_{path.replace('/', '_') or 'root'}"
        return handler

    app.add_url_rule(p, view_func=make_route(p), methods=["GET", "POST"])

@app.errorhandler(404)
def not_found(_):
    ip = client_ip()
    body = request.get_data(as_text=True)[:2000]
    qs = request.query_string.decode("utf-8", errors="ignore")[:1000]
    cls = classify_request(request.path, body, qs)
    log_event({
        "ts": now_iso(),
        "ip": ip,
        "method": request.method,
        "path": request.path,
        "query": qs,
        "user_agent": request.headers.get("User-Agent", ""),
        "classification": cls,
        "status": 404
    })
    return Response("Not Found", status=404)

if __name__ == "__main__":
    # Local dev
    app.run(host="0.0.0.0", port=8080, debug=True)
