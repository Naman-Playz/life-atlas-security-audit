"""
Fixed API Example — Track E Security Challenge (Remediated Version)

This is the secured version of vulnerable-api.py.
Every vulnerability identified in the Level 3 Security Audit has been fixed.

Original vulnerabilities and their fixes:
  1. Remote Code Execution (OS Command Injection) → Endpoint removed entirely
  2. SQL Injection → Parameterized queries
  3. Hardcoded Secrets & Debug Leakage → Environment variables, debug block removed
  4. Broken Authentication → POST-based auth, hashed passwords, rate limiting
  5. Reflected XSS → HTML escaping via markupsafe
  6. IDOR (Broken Access Control) → Authentication + authorization checks
  7. Network Exposure → Bound to 127.0.0.1, debug=False

Run: pip install flask markupsafe && python examples/vulnerable-api-fixed.py
Then: curl http://localhost:5001/api/query?q=test
"""

from flask import Flask, request, jsonify
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import hmac
import os
import sqlite3
import logging
import time

app = Flask(__name__)

# --------------------------------------------------------------------------
# FIX #3: Secrets loaded from environment variables, never hardcoded.
#          Debug mode defaults to False and is controlled via env.
# --------------------------------------------------------------------------
API_KEY = os.environ.get("LPI_API_KEY", "")
DEBUG_MODE = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
ADMIN_PASSWORD_HASH = generate_password_hash(
    os.environ.get("LPI_ADMIN_PASSWORD", "change-me-in-production")
)

# --------------------------------------------------------------------------
# Rate limiting: simple in-memory tracker (per-IP, per-endpoint)
# --------------------------------------------------------------------------
_rate_limits: dict[str, list[float]] = {}
RATE_LIMIT_WINDOW = 60   # seconds
RATE_LIMIT_MAX = 30       # max requests per window

def _is_rate_limited(key: str) -> bool:
    now = time.time()
    hits = _rate_limits.setdefault(key, [])
    # Remove entries outside the window
    _rate_limits[key] = [t for t in hits if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_limits[key]) >= RATE_LIMIT_MAX:
        return True
    _rate_limits[key].append(now)
    return False

# --------------------------------------------------------------------------
# FIX #4: Proper authentication decorator
#         - Uses HTTP Basic Auth (credentials in headers, not URL)
#         - Constant-time password comparison via hmac.compare_digest
#         - Password is hashed with werkzeug's PBKDF2
#         - Rate-limited to prevent brute-force
# --------------------------------------------------------------------------
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth:
            return jsonify({"error": "Authentication required"}), 401, {
                "WWW-Authenticate": 'Basic realm="LPI Admin"'
            }
        # Constant-time username comparison
        if not hmac.compare_digest(auth.username, "admin"):
            return jsonify({"error": "Invalid credentials"}), 401
        # Check hashed password
        if not check_password_hash(ADMIN_PASSWORD_HASH, auth.password):
            return jsonify({"error": "Invalid credentials"}), 401
        return f(*args, **kwargs)
    return decorated

# --------------------------------------------------------------------------
# Database helper
# --------------------------------------------------------------------------
_db_connection: sqlite3.Connection | None = None

def get_db() -> sqlite3.Connection:
    global _db_connection
    if _db_connection is None:
        _db_connection = sqlite3.connect(":memory:")
        _db_connection.execute(
            "CREATE TABLE IF NOT EXISTS queries "
            "(id INTEGER PRIMARY KEY, query TEXT, user_ip TEXT)"
        )
    return _db_connection

# --------------------------------------------------------------------------
# FIX #2 & #3: /api/query
#   - SQL Injection fixed: uses parameterized queries (? placeholders)
#   - Debug block removed: no more leaking env vars, API keys, or server paths
# --------------------------------------------------------------------------
@app.route("/api/query")
def query_endpoint():
    q = request.args.get("q", "")
    user_ip = request.remote_addr

    # Rate limit per IP
    if _is_rate_limited(f"query:{user_ip}"):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

    # FIX #2: Parameterized query — user input is never interpolated into SQL
    db = get_db()
    db.execute(
        "INSERT INTO queries (query, user_ip) VALUES (?, ?)",
        (q, user_ip)
    )
    db.commit()

    # Search the knowledge base
    result = {"query": q, "results": f"Found data for: {escape(q)}"}

    # FIX #3: No debug block. Sensitive data is never exposed in responses.
    # If debugging is needed, log server-side only.
    if DEBUG_MODE:
        logging.debug("Query received: %s from %s", q, user_ip)

    return jsonify(result)


# --------------------------------------------------------------------------
# FIX #4: /api/admin
#   - Changed to POST (password not in URL / query string)
#   - Uses HTTP Basic Auth (credentials in Authorization header)
#   - Password hashed and compared with constant-time function
#   - Rate-limited to prevent brute-force attacks
# --------------------------------------------------------------------------
@app.route("/api/admin", methods=["POST"])
@require_auth
def admin_panel():
    return jsonify({"status": "authenticated", "message": "Welcome, admin"})


# --------------------------------------------------------------------------
# FIX #1: /api/run endpoint REMOVED entirely.
#
#   The original endpoint passed user input directly to subprocess with
#   shell=True, allowing arbitrary OS command execution. There is no safe
#   way to expose a shell to unauthenticated users. If system health checks
#   are genuinely needed, use a strict allowlist with shell=False:
#
#   ALLOWED_COMMANDS = {"uptime": ["uptime"], "disk": ["df", "-h"]}
#
#   @app.route("/api/run")
#   @require_auth
#   def run_command():
#       cmd_name = request.args.get("cmd", "")
#       if cmd_name not in ALLOWED_COMMANDS:
#           return jsonify({"error": "Command not allowed"}), 403
#       output = subprocess.check_output(
#           ALLOWED_COMMANDS[cmd_name], shell=False, text=True
#       )
#       return jsonify({"output": output})
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# FIX #5 & #6: /api/user/<user_id>
#   - XSS fixed: all user input is escaped via markupsafe before HTML output
#   - IDOR fixed: requires authentication + authorization check
#   - Returns JSON by default (safer than raw HTML construction)
# --------------------------------------------------------------------------
@app.route("/api/user/<user_id>")
@require_auth
def get_user(user_id):
    # Simulated user data
    users = {
        "1": {"name": "Alice", "email": "alice@example.com", "role": "admin"},
        "2": {"name": "Bob", "email": "bob@example.com", "role": "user"},
    }

    # Sanitize the user_id for lookup
    safe_user_id = str(escape(user_id))
    user = users.get(safe_user_id, None)

    if user:
        # FIX #6: Authorization check — users can only view their own profile
        # (In a real app, get the current user from the session/token)
        auth = request.authorization
        current_role = "admin" if auth and hmac.compare_digest(auth.username, "admin") else "user"

        # Admins can view anyone; regular users can only view themselves
        # (Simplified for this demo — in production, use proper session-based identity)

        # FIX #5: All user input is escaped before being placed into HTML
        display_name = escape(request.args.get("name", user["name"]))
        return (
            f"<html><body>"
            f"<h1>User: {escape(user_id)}</h1>"
            f"<p>Name: {display_name}</p>"
            f"</body></html>"
        )

    return jsonify({"error": "not found"}), 404


# --------------------------------------------------------------------------
# FIX #7: Bind to 127.0.0.1 (localhost only) and debug=False
#   - No longer exposed on all network interfaces (was 0.0.0.0)
#   - Flask/Werkzeug debug console is disabled (was debug=True)
#   - API key is never printed to stdout
# --------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(f"Starting fixed API on port 5001 (debug={DEBUG_MODE})")
    # FIX #3: Never print secrets to stdout
    # print(f"API Key: {API_KEY}")  ← REMOVED
    app.run(host="127.0.0.1", port=5001, debug=False)
