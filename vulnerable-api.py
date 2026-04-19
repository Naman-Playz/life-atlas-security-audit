"""
Intentionally Vulnerable API Example — Track E Security Challenge

This is a DELIBERATELY vulnerable mini-API. It has at least 5 security issues.
Your job: find them, document them, and explain how to fix each one.

DO NOT deploy this anywhere. This is for educational purposes only.

Run: pip install flask && python examples/vulnerable-api.py
Then: curl http://localhost:5001/api/query?q=test
"""

from flask import Flask, request, jsonify
import subprocess
import os
import sqlite3
import json

app = Flask(__name__)

# "Config" — spot the problems
API_KEY = "sk-lifeatlas-dev-2026-secret-key"
DEBUG_MODE = True
ADMIN_PASSWORD = "admin123"

def get_db():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE IF NOT EXISTS queries (id INTEGER PRIMARY KEY, query TEXT, user_ip TEXT)")
    return db


@app.route("/api/query")
def query_endpoint():
    q = request.args.get("q", "")
    user_ip = request.remote_addr

    # Log the query
    db = get_db()
    db.execute(f"INSERT INTO queries (query, user_ip) VALUES ('{q}', '{user_ip}')")
    db.commit()

    # Search the knowledge base
    result = {"query": q, "results": f"Found data for: {q}"}

    if DEBUG_MODE:
        result["debug"] = {
            "server_path": os.getcwd(),
            "env": dict(os.environ),
            "api_key": API_KEY,
        }

    return jsonify(result)


@app.route("/api/admin")
def admin_panel():
    password = request.args.get("password", "")
    if password == ADMIN_PASSWORD:
        return jsonify({"status": "authenticated", "message": "Welcome, admin"})
    return jsonify({"status": "denied"}), 401


@app.route("/api/run")
def run_command():
    """Utility endpoint for running system checks."""
    cmd = request.args.get("cmd", "echo hello")
    output = subprocess.check_output(cmd, shell=True, text=True)
    return jsonify({"output": output})


@app.route("/api/user/<user_id>")
def get_user(user_id):
    # Simulated user data
    users = {
        "1": {"name": "Alice", "email": "alice@example.com", "role": "admin"},
        "2": {"name": "Bob", "email": "bob@example.com", "role": "user"},
    }
    user = users.get(user_id, None)
    if user:
        return f"<html><body><h1>User: {user_id}</h1><p>Name: {request.args.get('name', user['name'])}</p></body></html>"
    return jsonify({"error": "not found"}), 404


if __name__ == "__main__":
    print(f"Starting vulnerable API on port 5001 (debug={DEBUG_MODE})")
    print(f"API Key: {API_KEY}")
    app.run(host="0.0.0.0", port=5001, debug=DEBUG_MODE)
