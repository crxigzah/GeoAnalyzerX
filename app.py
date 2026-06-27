"""
GeoAnalyzerX Platform API
Deploy to Render.com (free tier)
Database: Supabase (free Postgres)
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib, os, datetime, secrets, psycopg2, psycopg2.extras
from functools import wraps

app = Flask(__name__)
CORS(app, origins=["*"])  # tighten to your domain later

# ── Database ──────────────────────────────────────────────
# Set DATABASE_URL in Render environment variables
# Format: postgresql://user:pass@host:5432/dbname
DATABASE_URL = os.environ.get("DATABASE_URL", "")

def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn

def init_db():
    """Create tables if they don't exist."""
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          SERIAL PRIMARY KEY,
            username    TEXT UNIQUE NOT NULL,
            email       TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            tier        TEXT DEFAULT 'free',
            created_at  TIMESTAMPTZ DEFAULT NOW(),
            last_login  TIMESTAMPTZ
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            user_id     INT REFERENCES users(id),
            created_at  TIMESTAMPTZ DEFAULT NOW(),
            expires_at  TIMESTAMPTZ DEFAULT NOW() + INTERVAL '30 days'
        );
    """)
    conn.commit()
    cur.close()
    conn.close()

# ── Helpers ───────────────────────────────────────────────
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Auth-Token") or request.json.get("token", "")
        if not token:
            return jsonify({"error": "No token"}), 401
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("""
            SELECT u.* FROM users u
            JOIN sessions s ON s.user_id = u.id
            WHERE s.token = %s AND s.expires_at > NOW()
        """, (token,))
        user = cur.fetchone()
        cur.close(); conn.close()
        if not user:
            return jsonify({"error": "Invalid or expired token"}), 401
        return f(user, *args, **kwargs)
    return decorated

# ── Routes ────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})

@app.route("/auth/register", methods=["POST"])
def register():
    data     = request.json or {}
    username = data.get("username", "").strip()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not username or len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    if not email or "@" not in email:
        return jsonify({"error": "Invalid email"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s) RETURNING id, username, email, tier, created_at",
            (username, email, hash_password(password))
        )
        user  = cur.fetchone()
        token = secrets.token_urlsafe(32)
        cur.execute("INSERT INTO sessions (token, user_id) VALUES (%s, %s)", (token, user["id"]))
        conn.commit()
        return jsonify({"token": token, "user": dict(user)}), 201
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "Username or email already taken"}), 409
    finally:
        cur.close(); conn.close()

@app.route("/auth/login", methods=["POST"])
def login():
    data     = request.json or {}
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT id, username, email, tier FROM users WHERE email = %s AND password = %s",
        (email, hash_password(password))
    )
    user = cur.fetchone()
    if not user:
        cur.close(); conn.close()
        return jsonify({"error": "Invalid email or password"}), 401

    token = secrets.token_urlsafe(32)
    cur.execute("INSERT INTO sessions (token, user_id) VALUES (%s, %s)", (token, user["id"]))
    cur.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user["id"],))
    conn.commit()
    cur.close(); conn.close()
    return jsonify({"token": token, "user": dict(user)})

@app.route("/auth/verify", methods=["POST"])
def verify():
    """Called by the Tampermonkey script on each load to verify token + get tier."""
    data  = request.json or {}
    token = data.get("token", "")
    if not token:
        return jsonify({"valid": False}), 401

    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        SELECT u.id, u.username, u.email, u.tier FROM users u
        JOIN sessions s ON s.user_id = u.id
        WHERE s.token = %s AND s.expires_at > NOW()
    """, (token,))
    user = cur.fetchone()
    cur.close(); conn.close()
    if not user:
        return jsonify({"valid": False}), 401
    return jsonify({"valid": True, "user": dict(user)})

@app.route("/admin/set_tier", methods=["POST"])
def admin_set_tier():
    """Admin endpoint to change a user's tier. Protected by ADMIN_KEY env var."""
    admin_key = os.environ.get("ADMIN_KEY", "")
    if not admin_key or request.json.get("admin_key") != admin_key:
        return jsonify({"error": "Forbidden"}), 403

    email = request.json.get("email", "").strip().lower()
    tier  = request.json.get("tier", "free")
    if tier not in ("free", "pro", "beta"):
        return jsonify({"error": "Invalid tier"}), 400

    conn = get_db()
    cur  = conn.cursor()
    cur.execute("UPDATE users SET tier = %s WHERE email = %s RETURNING username, email, tier", (tier, email))
    user = cur.fetchone()
    conn.commit(); cur.close(); conn.close()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"updated": dict(user)})

@app.route("/admin/users", methods=["GET"])
def admin_users():
    """List all users. Protected by ADMIN_KEY."""
    admin_key = os.environ.get("ADMIN_KEY", "")
    if not admin_key or request.args.get("admin_key") != admin_key:
        return jsonify({"error": "Forbidden"}), 403

    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT id, username, email, tier, created_at, last_login FROM users ORDER BY created_at DESC")
    users = [dict(u) for u in cur.fetchall()]
    cur.close(); conn.close()
    # Convert datetimes to strings
    for u in users:
        for k in ("created_at", "last_login"):
            if u[k]: u[k] = u[k].isoformat()
    return jsonify({"users": users, "count": len(users)})

if __name__ == "__main__":
    try: init_db()
    except Exception as e: print("DB init error:", e)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)), debug=False)
