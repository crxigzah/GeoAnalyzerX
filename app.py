"""
GeoAnalyzerX Platform API — v2.0 with Cloud Scene Library (Cloudflare R2)
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib, os, secrets, uuid, base64, io, time, threading, re, math
import pg8000.native
from urllib.parse import urlparse

app = Flask(__name__)
# Caps total request body size (generous for a base64-encoded screenshot,
# but blocks someone sending an enormous payload to waste server resources,
# inflate Supabase storage costs, or rack up Claude API costs).
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB
CORS(app, origins=[
    "https://geoanalyzerx.net",
    "https://www.geoanalyzerx.net",
    re.compile(r"^chrome-extension://.*$"),
    re.compile(r"^moz-extension://.*$"),
], supports_credentials=True, allow_headers=["Content-Type", "X-Admin-Key", "X-Admin-Token"])

# ── Config ────────────────────────────────────────────────
DATABASE_URL       = os.environ.get("DATABASE_URL", "")
import requests as http_requests

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
EMAIL_FROM     = os.environ.get("EMAIL_FROM", "GeoAnalyzerX <noreply@geoanalyzerx.net>")
ADMIN_KEY      = os.environ.get("ADMIN_KEY", "")

def send_email(to, subject, html):
    if not RESEND_API_KEY:
        print("RESEND_API_KEY not set, skipping email send")
        return False
    try:
        resp = http_requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={"from": EMAIL_FROM, "to": [to], "subject": subject, "html": html},
            timeout=10
        )
        return resp.status_code in (200, 201)
    except Exception as e:
        print("Email send error:", e)
        return False

def send_verification_email(email, username, code):
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#08080f;color:#e0e0f0;border-radius:16px;">
      <h1 style="color:#00c9a7;font-size:20px;">Verify your GeoAnalyzerX account</h1>
      <p style="color:#8888aa;font-size:14px;">Hi {username}, use the code below to verify your email and activate your account.</p>
      <div style="background:#1a1a2e;border:1px solid #2a2a3e;border-radius:12px;padding:20px;text-align:center;margin:20px 0;">
        <div style="font-size:32px;font-weight:800;letter-spacing:8px;color:#00c9a7;">{code}</div>
      </div>
      <p style="color:#5a5a7a;font-size:12px;">This code expires in 15 minutes. If you didn't sign up for GeoAnalyzerX, you can ignore this email.</p>
    </div>
    """
    return send_email(email, "Verify your GeoAnalyzerX account", html)
FRONTEND_URL       = os.environ.get("FRONTEND_URL", "https://geoanalyzerx.net")
SUPABASE_URL       = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY       = os.environ.get("SUPABASE_SERVICE_KEY", "")
STORAGE_BUCKET     = "scenes"

print(f"SUPABASE_URL: {'SET' if SUPABASE_URL else 'MISSING'}")
print(f"SUPABASE_KEY: {'SET' if SUPABASE_KEY else 'MISSING'}")

# ── Stripe ────────────────────────────────────────────────
import stripe
import pyotp, qrcode, io as _io, base64 as _b64

stripe.api_key          = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET   = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRO_PRICE_ID     = os.environ.get("STRIPE_PRO_PRICE_ID", "")

print(f"Stripe key loaded: {'YES' if stripe.api_key else 'MISSING'}")
print(f"Stripe price ID:   {'YES' if STRIPE_PRO_PRICE_ID else 'MISSING'}")
print(f"Stripe webhook:    {'YES' if STRIPE_WEBHOOK_SECRET else 'MISSING'}")


# ── DB ────────────────────────────────────────────────────
def get_db():
    url = urlparse(DATABASE_URL)
    return pg8000.native.Connection(
        host=url.hostname, port=url.port or 5432,
        database=url.path.lstrip('/'),
        user=url.username, password=url.password,
        ssl_context=True
    )

def init_db():
    if not DATABASE_URL:
        print("No DATABASE_URL"); return
    try:
        conn = get_db()
        conn.run("""CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
            tier TEXT DEFAULT 'free', totp_secret TEXT,
            totp_secret_pending TEXT, totp_enabled BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT NOW(), last_login TIMESTAMPTZ)""")
        try:
            conn.run("ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_until TIMESTAMPTZ")
            conn.run("ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason TEXT")
            conn.run("ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled BOOLEAN DEFAULT FALSE")
            conn.run("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE")
            conn.run("ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_code TEXT")
            conn.run("ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_expires TIMESTAMPTZ")
            conn.run("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE")
        except: pass
        conn.run("""CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, user_id INT REFERENCES users(id),
            created_at TIMESTAMPTZ DEFAULT NOW(),
            expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '30 days')""")
        conn.run("""CREATE TABLE IF NOT EXISTS scenes (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            country TEXT NOT NULL, state TEXT, region TEXT,
            lat FLOAT, lng FLOAT, r2_key TEXT NOT NULL,
            contributor_user_id TEXT,
            quality_score INT DEFAULT 0, times_used INT DEFAULT 0,
            uploaded_at TIMESTAMPTZ DEFAULT NOW())""")
        conn.run("""CREATE TABLE IF NOT EXISTS usage (
            user_id INT REFERENCES users(id),
            date DATE DEFAULT CURRENT_DATE,
            analyses INT DEFAULT 0,
            f7_captures INT DEFAULT 0,
            teachings INT DEFAULT 0,
            PRIMARY KEY (user_id, date))""")
        # Add columns if upgrading from old schema
        try:
            conn.run("ALTER TABLE usage ADD COLUMN IF NOT EXISTS f7_captures INT DEFAULT 0")
            conn.run("ALTER TABLE usage ADD COLUMN IF NOT EXISTS teachings INT DEFAULT 0")
        except: pass
        conn.run("CREATE INDEX IF NOT EXISTS idx_scenes_state ON scenes(state)")
        conn.run("CREATE INDEX IF NOT EXISTS idx_scenes_country_region ON scenes(country, region)")
        conn.close()
        print("DB init OK")
    except Exception as e:
        print("DB init error:", e)

def hp(p): return hashlib.sha256(p.encode()).hexdigest()  # legacy hash, kept only for migrating old accounts

def hash_password(p):
    """New accounts/password changes always use a salted, slow hash."""
    return generate_password_hash(p)

def verify_password(stored, plain):
    """Returns True/False. Supports both new salted hashes and legacy
    unsalted SHA-256 hashes (for accounts created before this upgrade)."""
    if not stored:
        return False
    if stored.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored, plain)
    # Legacy SHA-256 hash format
    return stored == hp(plain)

# ── Simple in-memory rate limiter ────────────────────────────
# Good enough for a single Render instance. Keyed by (bucket, identifier).
_rate_buckets = {}
_rate_lock = threading.Lock()

def rate_limited(bucket, identifier, max_attempts, window_seconds):
    """Returns True if this identifier has exceeded max_attempts within
    window_seconds for the given bucket (e.g. 'login', 'verify_email')."""
    key = f"{bucket}:{identifier}"
    now = time.time()
    with _rate_lock:
        attempts = _rate_buckets.get(key, [])
        attempts = [t for t in attempts if now - t < window_seconds]
        if len(attempts) >= max_attempts:
            _rate_buckets[key] = attempts
            return True
        attempts.append(now)
        _rate_buckets[key] = attempts
        return False

def client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"

def safe_error(e):
    """Logs the full exception server-side (visible in Render logs) but
    returns only a generic message to the client, so internal details like
    DB connection info, file paths, or query structure are never exposed."""
    print("Server error:", repr(e))
    return jsonify({"error": "Something went wrong. Please try again."}), 500

def validate_image_b64(image_b64, max_bytes=8 * 1024 * 1024):
    """Confirms the string is valid base64 that decodes to actual image
    bytes (checked via magic-byte signatures for JPEG/PNG/WEBP) and is
    within a sane size limit. Returns (ok, error_message)."""
    if not image_b64:
        return False, "No image provided"
    try:
        raw = base64.b64decode(image_b64, validate=True)
    except Exception:
        return False, "Invalid image data"
    if len(raw) > max_bytes:
        return False, "Image too large"
    if len(raw) < 100:
        return False, "Invalid image data"
    is_jpeg = raw[:3] == b'\xff\xd8\xff'
    is_png  = raw[:8] == b'\x89PNG\r\n\x1a\n'
    is_webp = raw[:4] == b'RIFF' and raw[8:12] == b'WEBP'
    if not (is_jpeg or is_png or is_webp):
        return False, "File must be a JPEG, PNG, or WEBP image"
    return True, None

# ── R2 / S3 helpers ───────────────────────────────────────
SUPABASE_URL       = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY       = os.environ.get("SUPABASE_SERVICE_KEY", "")  # service role key
STORAGE_BUCKET     = "scenes"

def upload_to_storage(image_b64: str, country: str, state: str, region: str):
    """Upload image to Supabase Storage."""
    try:
        import requests
        image_bytes = base64.b64decode(image_b64)
        key = f"{country}/{state or 'unknown'}/{region or 'central'}/{uuid.uuid4()}.jpg"
        url = f"{SUPABASE_URL}/storage/v1/object/{STORAGE_BUCKET}/{key}"
        headers = {
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "image/jpeg",
            "x-upsert": "true"
        }
        resp = requests.post(url, data=image_bytes, headers=headers, timeout=30)
        if resp.status_code in (200, 201):
            print(f"Storage upload OK: {key}")
            return key
        print(f"Storage upload failed: {resp.status_code} {resp.text[:200]}")
        return None
    except Exception as e:
        print("Storage upload error:", e)
        return None

def get_storage_image_b64(key: str):
    """Fetch image from Supabase Storage."""
    try:
        import requests
        url = f"{SUPABASE_URL}/storage/v1/object/{STORAGE_BUCKET}/{key}"
        headers = {"Authorization": f"Bearer {SUPABASE_KEY}"}
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return base64.b64encode(resp.content).decode()
        print(f"Storage fetch failed: {resp.status_code}")
        return None
    except Exception as e:
        print("Storage fetch error:", e)
        return None

# aliases so rest of code doesn't change
def upload_to_r2(image_b64, country, state, region):
    return upload_to_storage(image_b64, country, state, region)

def get_r2_image_b64(key):
    return get_storage_image_b64(key)

def get_r2_client():
    pass

def classify_region(lat, lng, state):
    """Classify lat/lng into a broad region quadrant."""
    if not lat or not lng:
        return 'central'
    STATE_CENTRES = {
        'victoria': (-37.0, 144.0), 'queensland': (-22.0, 144.0),
        'new south wales': (-32.0, 146.0), 'south australia': (-30.0, 135.0),
        'western australia': (-25.0, 121.0), 'northern territory': (-19.0, 133.0),
        'tasmania': (-42.0, 146.5),
    }
    centre = STATE_CENTRES.get((state or '').lower(), (-25.0, 133.0))
    ns = 'north' if float(lat) > centre[0] else 'south'
    ew = 'east'  if float(lng) > centre[1] else 'west'
    return f"{ns}{ew}"

def get_aus_state_from_coords(lat, lng):
    """Get Australian state from coordinates as fallback."""
    if not lat or not lng: return ''
    lat, lng = float(lat), float(lng)
    if lat < -39.5 and lng > 143.5 and lng < 149.5: return 'Tasmania'
    if lng < 129: return 'Western Australia'
    if lng >= 129 and lng <= 138 and lat > -25.996: return 'Northern Territory'
    if lng >= 129 and lng <= 141 and lat <= -25.996: return 'South Australia'
    if lng > 138 and lat > -29.0 and lng <= 153: return 'Queensland'
    if lng > 141:
        if lng < 144 and lat < -34.0: return 'Victoria'
        if 144 <= lng < 146 and lat < -36.0: return 'Victoria'
        if 146 <= lng < 148 and lat < -36.1: return 'Victoria'
        if 148 <= lng < 149 and lat < -37.0: return 'Victoria'
        if lng >= 149 and lat < -37.5: return 'Victoria'
        if lat <= -29.0: return 'New South Wales'
    return ''

# ── Health ────────────────────────────────────────────────
@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "Upload too large. Please use a smaller image."}), 413

@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "2.0.0"})

# ── Auth ──────────────────────────────────────────────────
@app.route("/auth/register", methods=["POST", "OPTIONS"])
def register():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    username = d.get("username","").strip()
    email    = d.get("email","").strip().lower()
    password = d.get("password","")
    if rate_limited("register_ip", client_ip(), max_attempts=10, window_seconds=3600):
        return jsonify({"error": "Too many accounts created from this network. Try again later."}), 429
    if len(username)<3: return jsonify({"error":"Username must be at least 3 characters"}),400
    if len(username)>32: return jsonify({"error":"Username must be 32 characters or fewer"}),400
    if not re.match(r'^[A-Za-z0-9_]+$', username):
        return jsonify({"error":"Username can only contain letters, numbers, and underscores"}),400
    if "@" not in email: return jsonify({"error":"Invalid email"}),400
    if len(password)<6: return jsonify({"error":"Password must be at least 6 characters"}),400
    try:
        conn  = get_db()
        verify_code = str(secrets.randbelow(900000) + 100000)  # 6-digit code
        rows  = conn.run(
            """INSERT INTO users (username,email,password,verify_code,verify_expires)
               VALUES (:u,:e,:p,:c,NOW() + INTERVAL '15 minutes')
               RETURNING id,username,email,tier""",
            u=username, e=email, p=hash_password(password), c=verify_code)
        user  = {"id":rows[0][0],"username":rows[0][1],"email":rows[0][2],"tier":rows[0][3]}
        token = secrets.token_urlsafe(32)
        conn.run("INSERT INTO sessions (token,user_id) VALUES (:t,:uid)", t=token, uid=user["id"])
        conn.close()
        send_verification_email(email, username, verify_code)
        return jsonify({"token":token,"user":user,"needs_verification":True}), 201
    except Exception as e:
        err = str(e)
        if "unique" in err.lower(): return jsonify({"error":"Username or email already taken"}),409
        return safe_error(e)

@app.route("/auth/verify_email", methods=["POST", "OPTIONS"])
def verify_email():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token = d.get("token", "")
    code  = d.get("code", "").strip()
    if not token or not code:
        return jsonify({"error": "Token and code required"}), 400
    if rate_limited("verify_email", token, max_attempts=8, window_seconds=900):
        return jsonify({"error": "Too many attempts. Please request a new code and try again shortly."}), 429
    try:
        conn = get_db()
        rows = conn.run("""SELECT u.id, u.verify_code, u.verify_expires, u.email_verified
            FROM users u JOIN sessions s ON s.user_id=u.id
            WHERE s.token=:t""", t=token)
        if not rows:
            conn.close(); return jsonify({"error": "Invalid session"}), 401
        user_id, stored_code, expires, already_verified = rows[0]
        if already_verified:
            conn.close(); return jsonify({"success": True, "already_verified": True})
        if not stored_code or stored_code != code:
            conn.close(); return jsonify({"error": "Incorrect code"}), 400
        if expires and str(expires) < str(conn.run("SELECT NOW()")[0][0]):
            conn.close(); return jsonify({"error": "Code expired, please request a new one"}), 400
        conn.run("UPDATE users SET email_verified=TRUE, verify_code=NULL WHERE id=:uid", uid=user_id)
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return safe_error(e)

@app.route("/auth/resend_code", methods=["POST", "OPTIONS"])
def resend_code():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token = d.get("token", "")
    if not token:
        return jsonify({"error": "Invalid session"}), 401
    if rate_limited("resend_code", token, max_attempts=3, window_seconds=600):
        return jsonify({"error": "Please wait a few minutes before requesting another code."}), 429
    try:
        conn = get_db()
        rows = conn.run("""SELECT u.id, u.username, u.email, u.email_verified FROM users u
            JOIN sessions s ON s.user_id=u.id WHERE s.token=:t""", t=token)
        if not rows:
            conn.close(); return jsonify({"error": "Invalid session"}), 401
        user_id, username, email, verified = rows[0]
        if verified:
            conn.close(); return jsonify({"error": "Already verified"}), 400
        new_code = str(secrets.randbelow(900000) + 100000)
        conn.run("UPDATE users SET verify_code=:c, verify_expires=NOW() + INTERVAL '15 minutes' WHERE id=:uid",
                  c=new_code, uid=user_id)
        conn.close()
        send_verification_email(email, username, new_code)
        return jsonify({"success": True})
    except Exception as e:
        return safe_error(e)

@app.route("/auth/request_verification", methods=["POST", "OPTIONS"])
def request_verification():
    """For accounts that registered but never verified, and are now stuck
    unable to log in with no way back into the code-entry screen. Re-checks
    email+password, then issues a fresh session token (same shape as
    register()'s) and a new code, so the frontend can route them back into
    the verify-code UI without fully logging them in."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    email    = d.get("email","").strip().lower()
    password = d.get("password","")
    if rate_limited("request_verification_ip", client_ip(), max_attempts=10, window_seconds=600):
        return jsonify({"error": "Too many attempts. Try again later."}), 429
    if email and rate_limited("request_verification_email", email, max_attempts=5, window_seconds=600):
        return jsonify({"error": "Too many attempts for this account. Try again later."}), 429
    try:
        conn = get_db()
        rows = conn.run("SELECT id,username,email,tier,password,email_verified FROM users WHERE email=:e", e=email)
        if not rows or not verify_password(rows[0][4], password):
            conn.close(); return jsonify({"error":"Invalid email or password"}),401
        user_id, username, email, tier, _, verified = rows[0]
        if verified:
            conn.close(); return jsonify({"error":"This account is already verified. Try signing in normally."}), 400
        new_code = str(secrets.randbelow(900000) + 100000)
        conn.run("UPDATE users SET verify_code=:c, verify_expires=NOW() + INTERVAL '15 minutes' WHERE id=:uid",
                  c=new_code, uid=user_id)
        token = secrets.token_urlsafe(32)
        conn.run("INSERT INTO sessions (token,user_id) VALUES (:t,:uid)", t=token, uid=user_id)
        conn.close()
        send_verification_email(email, username, new_code)
        user = {"id": user_id, "username": username, "email": email, "tier": tier}
        return jsonify({"token": token, "user": user, "needs_verification": True})
    except Exception as e:
        return safe_error(e)

@app.route("/auth/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    email    = d.get("email","").strip().lower()
    password = d.get("password","")
    totp_code = d.get("totp_code", "").strip()

    if rate_limited("login_ip", client_ip(), max_attempts=20, window_seconds=600):
        return jsonify({"error": "Too many login attempts from this network. Try again in a few minutes."}), 429
    if email and rate_limited("login_email", email, max_attempts=8, window_seconds=600):
        return jsonify({"error": "Too many login attempts for this account. Try again in a few minutes."}), 429

    try:
        conn = get_db()
        rows = conn.run("""SELECT id,username,email,tier,banned_until,ban_reason,disabled,email_verified,
                            password,totp_enabled,totp_secret FROM users WHERE email=:e""", e=email)
        if not rows or not verify_password(rows[0][8], password):
            conn.close(); return jsonify({"error":"Invalid email or password"}),401
        # Transparently upgrade legacy SHA-256 hashes to salted hashes on successful login
        if not rows[0][8].startswith(("scrypt:", "pbkdf2:")):
            conn.run("UPDATE users SET password=:p WHERE id=:uid", p=hash_password(password), uid=rows[0][0])
        if rows[0][6]:
            conn.close()
            return jsonify({"error": "Account disabled", "code": "disabled"}), 403
        if not rows[0][7]:
            conn.close()
            return jsonify({"error": "Please verify your email before logging in", "code": "unverified"}), 403
        banned_until = rows[0][4]
        if banned_until and str(banned_until) != 'None':
            conn.close()
            return jsonify({
                "error": "Account banned",
                "code": "banned",
                "banned_until": str(banned_until),
                "ban_reason": rows[0][5] or "Violation of terms of service"
            }), 403
        totp_enabled, totp_secret = rows[0][9], rows[0][10]
        if totp_enabled:
            if not totp_code:
                conn.close()
                return jsonify({"error": "2FA code required", "code": "totp_required"}), 401
            if not pyotp.TOTP(totp_secret).verify(totp_code, valid_window=1):
                conn.close()
                return jsonify({"error": "Invalid 2FA code", "code": "totp_invalid"}), 401
        user  = {"id":rows[0][0],"username":rows[0][1],"email":rows[0][2],"tier":rows[0][3]}
        token = secrets.token_urlsafe(32)
        conn.run("INSERT INTO sessions (token,user_id) VALUES (:t,:uid)", t=token, uid=user["id"])
        conn.run("UPDATE users SET last_login=NOW() WHERE id=:uid", uid=user["id"])
        conn.close()
        return jsonify({"token":token,"user":user})
    except Exception as e:
        return safe_error(e)

@app.route("/auth/logout", methods=["POST", "OPTIONS"])
def logout():
    """Revokes the session token server-side. Previously sign-out only
    cleared the token locally, leaving the session valid for up to 30
    days even after the user 'logged out' — so a stolen/leaked token
    kept working regardless."""
    if request.method == "OPTIONS": return jsonify({}), 200
    token = (request.json or {}).get("token","")
    if not token: return jsonify({"success": True})
    try:
        conn = get_db()
        conn.run("DELETE FROM sessions WHERE token=:t", t=token)
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return safe_error(e)

@app.route("/auth/verify", methods=["POST", "OPTIONS"])
def verify():
    if request.method == "OPTIONS": return jsonify({}), 200
    token = (request.json or {}).get("token","")
    if not token: return jsonify({"valid":False}),401
    try:
        conn = get_db()
        rows = conn.run("""SELECT u.id,u.username,u.email,u.tier,u.created_at,u.banned_until,u.ban_reason,u.email_verified FROM users u
            JOIN sessions s ON s.user_id=u.id
            WHERE s.token=:t AND s.expires_at>NOW()""", t=token)
        conn.close()
        if not rows: return jsonify({"valid":False}),401
        banned_until = rows[0][5]
        if banned_until and str(banned_until) != 'None':
            return jsonify({
                "valid": False, "code": "banned",
                "banned_until": str(banned_until),
                "ban_reason": rows[0][6] or "Violation of terms of service"
            }), 403
        user = {"id":rows[0][0],"username":rows[0][1],"email":rows[0][2],"tier":rows[0][3],"created_at":str(rows[0][4]),"email_verified":bool(rows[0][7])}
        return jsonify({"valid":True,"user":user})
    except Exception as e:
        print("Server error:", repr(e))
        return jsonify({"valid":False,"error":"Something went wrong. Please try again."}),500

@app.route("/auth/change-password", methods=["POST", "OPTIONS"])
def change_password():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token = d.get("token",""); current = d.get("current_password",""); new_pwd = d.get("new_password","")
    if len(new_pwd) < 6: return jsonify({"error": "New password must be at least 6 characters"}), 400
    try:
        conn = get_db()
        rows = conn.run("""SELECT u.id, u.password FROM users u
            JOIN sessions s ON s.user_id=u.id
            WHERE s.token=:t AND s.expires_at>NOW()""", t=token)
        conn.close()
        if not rows: return jsonify({"error": "Invalid token"}), 401
        user_id, pwd_hash = rows[0][0], rows[0][1]
    except Exception as e:
        return safe_error(e)
    if not verify_password(pwd_hash, current):
        return jsonify({"error": "Current password is incorrect"}), 400
    try:
        conn = get_db()
        conn.run("UPDATE users SET password=:p WHERE id=:uid", p=hash_password(new_pwd), uid=user_id)
        conn.close()
    except Exception as e:
        return safe_error(e)
    return jsonify({"changed": True})

# ── 2FA ───────────────────────────────────────────────────
@app.route("/auth/2fa/setup", methods=["POST", "OPTIONS"])
def setup_2fa():
    if request.method == "OPTIONS": return jsonify({}), 200
    token = (request.json or {}).get("token", "")
    try:
        conn = get_db()
        rows = conn.run("""SELECT u.id, u.email, u.username FROM users u
            JOIN sessions s ON s.user_id=u.id
            WHERE s.token=:t AND s.expires_at>NOW()""", t=token)
        conn.close()
        if not rows: return jsonify({"error": "Invalid token"}), 401
        user_id, email, username = rows[0][0], rows[0][1], rows[0][2]
    except Exception as e:
        return safe_error(e)
    secret = pyotp.random_base32()
    totp   = pyotp.TOTP(secret)
    uri    = totp.provisioning_uri(name=email, issuer_name="GeoAnalyzerX")
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#00c9a7", back_color="#0d0d12")
    buf = _io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = _b64.b64encode(buf.getvalue()).decode()
    try:
        conn = get_db()
        conn.run("UPDATE users SET totp_secret_pending=:s WHERE id=:uid", s=secret, uid=user_id)
        conn.close()
    except Exception as e:
        return safe_error(e)
    return jsonify({"secret": secret, "qr": qr_b64})

@app.route("/auth/2fa/verify", methods=["POST", "OPTIONS"])
def verify_2fa_setup():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token, code = d.get("token",""), d.get("code","")
    try:
        conn = get_db()
        rows = conn.run("""SELECT u.id, u.totp_secret_pending FROM users u
            JOIN sessions s ON s.user_id=u.id
            WHERE s.token=:t AND s.expires_at>NOW()""", t=token)
        conn.close()
        if not rows: return jsonify({"error": "Invalid token"}), 401
        user_id, pending = rows[0][0], rows[0][1]
    except Exception as e:
        return safe_error(e)
    if not pending: return jsonify({"error": "No pending 2FA setup"}), 400
    if not pyotp.TOTP(pending).verify(code, valid_window=1):
        return jsonify({"error": "Incorrect code — try again"}), 400
    try:
        conn = get_db()
        conn.run("UPDATE users SET totp_secret=:s, totp_enabled=TRUE, totp_secret_pending=NULL WHERE id=:uid",
                 s=pending, uid=user_id)
        conn.close()
    except Exception as e:
        return safe_error(e)
    return jsonify({"enabled": True})

@app.route("/auth/2fa/disable", methods=["POST", "OPTIONS"])
def disable_2fa():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token, code = d.get("token",""), d.get("code","")
    try:
        conn = get_db()
        rows = conn.run("""SELECT u.id, u.totp_secret FROM users u
            JOIN sessions s ON s.user_id=u.id
            WHERE s.token=:t AND s.expires_at>NOW()""", t=token)
        conn.close()
        if not rows: return jsonify({"error": "Invalid token"}), 401
        user_id, secret = rows[0][0], rows[0][1]
    except Exception as e:
        return safe_error(e)
    if not secret: return jsonify({"error": "2FA not enabled"}), 400
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return jsonify({"error": "Incorrect code"}), 400
    try:
        conn = get_db()
        conn.run("UPDATE users SET totp_secret=NULL, totp_enabled=FALSE WHERE id=:uid", uid=user_id)
        conn.close()
    except Exception as e:
        return safe_error(e)
    return jsonify({"disabled": True})

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

FREE_DAILY_LIMIT = 10

SYSTEM_PROMPT = """You are an elite GeoGuessr analyst at world champion level. This is a screenshot of the GeoGuessr browser. The Street View scene is on the LEFT side. Ignore the GeoGuessr UI panel on the right.

POLE ANALYSIS RULES — READ FIRST:
Before mentioning ANY pole feature, ask yourself: "Can I clearly see this detail, or am I guessing?"
- If poles are DISTANT (small in frame, further than 50m): say "poles visible but too distant to identify type"
- If poles are CLOSE and CLEAR: describe exactly what you see on the pole BODY and TOP
- NEVER claim green base, Stobie beams, L-shaped crossbar, disc insulators unless you can clearly see them
- When uncertain about poles: say so and use landscape/other clues instead

ANALYSIS FRAMEWORK:

STEP 1 — DRIVING SIDE: Left or right?

STEP 2 — SCRIPT/LANGUAGE: Read every word visible. Script = instant country confirmation.
Cyrillic=Russia/Ukraine/Bulgaria/Serbia/Mongolia. Arabic=Middle East/North Africa. Hebrew=Israel.
Greek=Greece/Cyprus. Thai(circles at stroke ends)=Thailand. Khmer(hooks at top)=Cambodia.
Korean Hangul(round blocky)=South Korea. Japanese(hiragana+kanji)=Japan. Chinese(square complex)=China/Taiwan.
Hindi(line above letters)=India. Georgian(curvy unique)=Georgia. Armenian(angular unique)=Armenia.

STEP 3 — GOOGLE CAR META (pan down, look at car shadow or bonnet):
Massive black snorkel front right = KENYA 100%.
4 roof bars one with black tape right end = GHANA.
Large pickup truck + white police car following = NIGERIA.
Red car + long antenna = UKRAINE.
Camping equipment on roof = MONGOLIA.
White car white roof rack = KYRGYZSTAN.
Very low to ground = JAPAN or SWITZERLAND.
Stubby antenna white car = ECUADOR.
Ghostly black front = ARGENTINA or URUGUAY.
White rear visible = CHILE.
Red Google car = usually WESTERN AUSTRALIA.
Dark grey snorkel = usually NSW or ACT Australia.

STEP 4 — ROAD LINES:
Yellow centre lines = Americas (USA/Canada/Mexico/Brazil/Argentina/Colombia/Chile) + Iceland + Norway.
OUTER yellow lines = SOUTH AFRICA only worldwide.
Triple lines double yellow + white dashes = URUGUAY only in Americas.
White lines = Europe/Asia/Africa/Oceania/Australia.
Blue rumble strips = SOUTH KOREA.

STEP 5 — BOLLARDS (only if clearly visible and close):
Black+yellow bands = QUEENSLAND ONLY.
Black+white diagonal stripes = WESTERN AUSTRALIA ONLY.
Red reflector all the way around = NEW ZEALAND (Australia = front only).
Red diagonal stripe wrapping = POLAND.
Fluorescent orange in black section = CZECH or SLOVAKIA.
Rounded cylindrical reflector all around = FRANCE.
Yellow bollards = ICELAND or SPAIN.
Obelisk alternating black+white = THAILAND.
White bollard large brown base = WESTERN AUSTRALIA.

STEP 6 — POLES (ONLY IF CLEARLY VISIBLE AND CLOSE — otherwise skip):
If poles are small or far: do NOT describe specific features. Say "distant poles, type unclear".
STOBIE (SA): concrete centre + thick steel H-beams BOTH sides full height = South Australia. VERY RARE.
VIC: round concrete + 3 DISC insulators (2 sides flat + 1 vertical) = Victoria.
QLD: insulators tilt upward at crossbar ends like a smile = Queensland.
NT: rusty brown metal tube with holes = Northern Territory.
TAS: metal L-shaped crossbar at top OR olive green rectangular guard clamped around pole = Tasmania.
WA: green painted base section = Western Australia.
Dense tangled wires everywhere = JAPAN.
Holey poles (large holes all down pole) = HUNGARY or ROMANIA.
Ladder poles (horizontal supports like ladder) = BRAZIL or NIGERIA.

STEP 7 — LANDSCAPE (use this when poles/bollards are unclear — very reliable):
Orange/red gravel road + low scrubby eucalyptus + flat = Western Australia or South Australia inland.
Dark red soil + bright green grass + dark tree trunks = Darwin NT specifically.
Orange termite mounds from red dirt = Northern Territory Australia.
Tall dense green sugarcane crops lining road + tropical mountains = far north Queensland.
Grass trees (dark trunk, long spiky tufts) = Western Australia ONLY.
Flat golden/brown dry grass + scattered eucalyptus = inland NSW or SA.
Green rolling hills + dense eucalyptus = Tasmania or Victoria.
Vast flat steppe no trees = Mongolia/Kazakhstan/central Russia.
Birch trees white bark = Russia/Scandinavia/Baltic.
Saguaro cactus with arms = Arizona USA ONLY.
Acacia trees flat savanna = sub-Saharan Africa.
Dense tropical jungle red laterite soil = equatorial Africa or Amazon Brazil.
Terraced rice paddies = SE Asia/Japan/China south.
Olive groves dry hills = Mediterranean Spain/Italy/Greece/Turkey.
Fjords dramatic mountains = Norway.
Almost no trees only grass volcanic = Iceland.
Bare treeless tabletop mountains horizontal ridges = Lesotho.
Lavender fields = Provence France.
Eucalyptus plantations uniform pale bark = Australia/Portugal/Brazil/East Africa.
Ferns in forest = New Zealand.

STEP 8 — ARCHITECTURE AND COMMERCIAL CLUES:
Soviet grey concrete blocks = Russia/Ukraine/Eastern Europe.
Houses on stilts wide verandas = Queensland Australia.
Round thatched huts = Lesotho/sub-Saharan Africa.
White cubic flat roofs = Greece/Mediterranean.
Half-timbered Fachwerk = Germany.
Gas station brands: YPF=Argentina. Petrobras=Brazil.
Website TLDs on signs: .co.za=SA. .co.nz=NZ. .com.au=Australia. .pl=Poland.

ANTI-HALLUCINATION RULES:
- If no pole is clearly visible or close enough to identify: skip pole analysis entirely.
- Never claim to see a feature (green base, steel beams, disc insulators, L-shape) unless you can genuinely see it.
- If image shows only landscape and distant poles: lead with landscape analysis.
- Ambiguous Australian concrete pole = VICTORIA by default, not SA.

Format EXACTLY as:
POLE DESCRIPTION: [what you literally see clearly, or "poles distant/not visible - using landscape clues"]
LOCATION: [Country / State / Region]
CONFIDENCE: [High/Medium/Low]
KEY CLUE: [the single most clearly visible detail that drives your conclusion]
DETAIL: [2-3 sentences based only on what is actually visible]"""

def call_claude(messages, system=None, max_tokens=400):
    """Call Claude API via Render."""
    import requests as req
    if not ANTHROPIC_API_KEY:
        raise Exception("ANTHROPIC_API_KEY not configured on server")
    payload = {
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": max_tokens,
        "messages": messages
    }
    if system:
        payload["system"] = system
    resp = req.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        },
        json=payload,
        timeout=30
    )
    data = resp.json()
    if "error" in data:
        raise Exception(data["error"].get("message", str(data["error"])))
    return data["content"][0]["text"].strip()

def get_user_from_token(token):
    """Returns (user_id, tier) or (None, None)."""
    if not token:
        return None, None
    try:
        conn = get_db()
        rows = conn.run("""SELECT u.id, u.tier FROM users u
            JOIN sessions s ON s.user_id=u.id
            WHERE s.token=:t AND s.expires_at>NOW()""", t=token)
        conn.close()
        if rows:
            return rows[0][0], rows[0][1]
    except Exception:
        pass
    return None, None

FREE_DAILY_LIMIT = 10

def check_and_increment_usage(user_id, counter='analyses'):
    """Returns (allowed, remaining). Increments counter if allowed."""
    if not user_id:
        return False, 0
    try:
        conn = get_db()
        rows = conn.run(f"""SELECT {counter} FROM usage
            WHERE user_id=:uid AND date=CURRENT_DATE""", uid=user_id)
        count = rows[0][0] if rows else 0
        if count >= FREE_DAILY_LIMIT:
            conn.close()
            return False, 0
        if rows:
            conn.run(f"""UPDATE usage SET {counter} = {counter} + 1
                WHERE user_id=:uid AND date=CURRENT_DATE""", uid=user_id)
        else:
            conn.run(f"""INSERT INTO usage (user_id, date, {counter})
                VALUES (:uid, CURRENT_DATE, 1)""", uid=user_id)
        conn.close()
        return True, FREE_DAILY_LIMIT - count - 1
    except Exception as e:
        print("Usage check error:", e)
        return True, -1  # fail open

# ── AI Endpoints ──────────────────────────────────────────
@app.route("/ai/analyse", methods=["POST", "OPTIONS"])
def ai_analyse():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token     = d.get("token", "")
    image_b64 = d.get("image", "")
    country   = d.get("country", "")

    if not image_b64:
        return jsonify({"error": "No image provided"}), 400
    img_ok, img_err = validate_image_b64(image_b64)
    if not img_ok:
        return jsonify({"error": img_err}), 400

    user_id, tier = get_user_from_token(token)
    if not user_id:
        return jsonify({"error": "Not logged in", "code": "auth"}), 401

    if rate_limited("ai_analyse", str(user_id), max_attempts=20, window_seconds=60):
        return jsonify({"error": "Too many requests, please slow down."}), 429

    if tier != "pro":
        # Free users cannot use the Analyse button at all
        return jsonify({
            "error": "Pro required",
            "code": "pro",
            "message": "The AI Analyse button is a Pro feature. Upgrade to Pro for full AI scene analysis with exact GPS coordinates.",
        }), 403

    try:
        known_location = d.get("known_location", "")
        if known_location:
            prompt = (
                f"CONFIRMED LOCATION: {known_location}. You know exactly where this is.\n"
                f"Look at this Street View scene and identify the visual clues that confirm it is {known_location}.\n"
                f"Focus on what you can ACTUALLY SEE. Output ONLY these 5 lines, plain text, no markdown:\n"
                f"POLE DESCRIPTION: [what you see or 'no clear pole visible']\n"
                f"LOCATION: {known_location}\n"
                f"CONFIDENCE: High (coordinates confirmed)\n"
                f"KEY CLUE: [the single most visible feature that identifies this as {known_location.split(',')[0]}]\n"
                f"DETAIL: [2 sentences about what you see that confirms this location]"
            )
        else:
            prompt = (
                f"Country hint: {country or 'unknown'}. Analyse this Street View scene.\n"
                f"Always identify the SPECIFIC STATE or REGION, not just the country.\n"
                f"Output ONLY these 5 lines, plain text, no markdown:\n"
                f"POLE DESCRIPTION: [what you see or 'no clear pole visible']\n"
                f"LOCATION: [Country / State / Region]\n"
                f"CONFIDENCE: [High/Medium/Low]\n"
                f"KEY CLUE: [most specific visible detail]\n"
                f"DETAIL: [2 sentences]"
            )
        result = call_claude([{
            "role": "user",
            "content": [
                {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": image_b64}},
                {"type": "text", "text": prompt}
            ]
        }], system=SYSTEM_PROMPT, max_tokens=400)
        return jsonify({"result": result, "tier": tier})
    except Exception as e:
        return safe_error(e)

@app.route("/ai/teaching", methods=["POST", "OPTIONS"])
def ai_teaching():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token        = d.get("token", "")
    image_b64    = d.get("image", "")
    correct_name = d.get("correct_name", "")
    distance_km  = d.get("distance_km", "?")
    ref_images   = d.get("ref_images", [])  # list of b64 from cloud library

    if not image_b64:
        return jsonify({"error": "No image"}), 400
    img_ok, img_err = validate_image_b64(image_b64)
    if not img_ok:
        return jsonify({"error": img_err}), 400

    user_id, tier = get_user_from_token(token)
    if not user_id:
        return jsonify({"error": "Not logged in", "code": "auth"}), 401

    if rate_limited("ai_teaching", str(user_id), max_attempts=20, window_seconds=60):
        return jsonify({"error": "Too many requests, please slow down."}), 429

    # Teaching counts against teachings limit
    if tier != "pro":
        allowed, remaining = check_and_increment_usage(user_id, 'teachings')
        if not allowed:
            return jsonify({
                "error": "Daily limit reached",
                "code": "limit",
                "message": f"You've used all {FREE_DAILY_LIMIT} free training guides for today. Upgrade to Pro for unlimited access, or come back tomorrow.",
                "remaining": 0
            }), 429

    try:
        content = [
            {"type": "text", "text": f"PLAYER'S SCENE (what they were looking at this round):"},
            {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": image_b64}},
            {"type": "text", "text": f"The correct location is {correct_name}."}
        ]
        # Add reference images from the correct location
        if ref_images:
            content.append({"type": "text", "text": f"REFERENCE IMAGES from {correct_name} (for comparison):"})
            for i, ref_b64 in enumerate(ref_images[:2]):
                content.append({"type": "text", "text": f"Reference {i+1}:"})
                content.append({"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": ref_b64}})

        content.append({"type": "text", "text": (
            f"You are an elite GeoGuessr coach. The player guessed wrong — the correct location is {correct_name}.\n\n"
            f"Look at the PLAYER'S SCENE and identify the strongest visual clues that PROVE it is {correct_name}.\n\n"
            "PRIORITY ORDER for clues (most reliable first):\n"
            "1. SOIL COLOUR — red/orange laterite, pale sandy, dark volcanic, grey clay etc\n"
            "2. VEGETATION — specific tree species, grass type, scrub density\n"
            "3. ROAD SURFACE & COLOUR — tarmac colour, gravel colour, road width\n"
            "4. LANDSCAPE — flat/hilly/mountainous, cleared/forested, agricultural patterns\n"
            "5. INFRASTRUCTURE — fencing style, power poles, buildings\n\n"
            "Rules:\n"
            "- CRITICAL: Output PLAIN TEXT ONLY. No markdown, no asterisks (**), no headers (#). Just raw text.\n"
            "- KEY CLUE: ONE specific thing you can actually SEE in the image (not abstract concepts)\n"
            "- Each LESSON must describe something VISIBLE IN THE SCENE\n"
            "- TRICKY must name ONE specific Australian state or country that looks similar and state the SINGLE visual difference\n"
            "- Never mention things you cannot clearly see\n\n"
            "Format EXACTLY as:\n"
            "KEY CLUE: [specific visible feature + WHY it proves this location, e.g. 'Red laterite soil — this iron-rich volcanic soil is only found in WA and NT, not in eastern Australia's grey/sandy soils']\n"
            "LESSON 1: [visible clue 1 and what it tells you about this location]\n"
            "LESSON 2: [visible clue 2]\n"
            "LESSON 3: [visible clue 3]\n"
            "TRICKY: [specific place it looks like, e.g. 'Western Australia' or 'New South Wales', and the ONE visual difference]"
        )})

        result = call_claude([{"role": "user", "content": content}], max_tokens=350)
        return jsonify({"teaching": result})
    except Exception as e:
        return safe_error(e)

@app.route("/ai/chat", methods=["POST", "OPTIONS"])
def ai_chat():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token        = d.get("token", "")
    message      = d.get("message", "").strip()
    last_analysis = d.get("last_analysis", "")

    if not message:
        return jsonify({"error": "Empty message"}), 400

    user_id, tier = get_user_from_token(token)
    if not user_id:
        return jsonify({"error": "Not logged in", "code": "auth"}), 401

    if rate_limited("ai_chat", str(user_id), max_attempts=30, window_seconds=60):
        return jsonify({"error": "Too many requests, please slow down."}), 429

    # Chat only for pro users
    if tier != "pro":
        return jsonify({
            "error": "Pro required",
            "code": "pro",
            "message": "GeoX chat is a Pro feature. Upgrade to Pro for unlimited AI chat."
        }), 403

    try:
        system = """You are GeoX, an expert GeoGuessr analyst who teaches players after they guessed WRONG.

YOUR JOB IS TO TEACH, NOT TO PLEASE. The player already guessed incorrectly — your role is to help them understand WHY they were wrong and what they should have seen. You know the correct location with certainty.

CRITICAL RULES:
- NEVER agree with the player if they are factually wrong. If they say "there were no termite mounds" but the correct location is Northern Territory where termite mounds are common, firmly correct them: tell them what the real visual evidence was and why it points to the correct location regardless of what they think they saw.
- NEVER say things like "you're right, that was an oversight in my analysis" or "fair point" or "I can see why you'd think that." You are not wrong — the player is. Hold your ground with specific evidence.
- If the player correctly identifies something, acknowledge it briefly, but immediately redirect to why the overall location identification was still wrong.
- Be direct, confident, and educational. 2-4 sentences max.
- Plain text only — no markdown, no bullet points, no asterisks.
- Always reference the specific correct location and the specific visual clues that prove it.

The context you receive includes the CORRECT LOCATION, the dead giveaway clue, key visual evidence, and what the player guessed wrong. Use all of this to correct them firmly."""
        result = call_claude([{
            "role": "user",
            "content": f"{last_analysis[:600]}\n\nPlayer: {message}"
        }], system=system, max_tokens=350)
        return jsonify({"reply": result})
    except Exception as e:
        return safe_error(e)

@app.route("/ai/usage", methods=["POST", "OPTIONS"])
def ai_usage():
    """Return today's usage for a user."""
    if request.method == "OPTIONS": return jsonify({}), 200
    token = (request.json or {}).get("token", "")
    user_id, tier = get_user_from_token(token)
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401
    if tier == "pro":
        return jsonify({"used": 0, "limit": -1, "remaining": -1, "tier": "pro",
                        "f7_used": 0, "teachings_used": 0})
    try:
        conn = get_db()
        rows = conn.run("""SELECT analyses, f7_captures, teachings FROM usage
            WHERE user_id=:uid AND date=CURRENT_DATE""", uid=user_id)
        conn.close()
        analyses  = rows[0][0] if rows else 0
        f7        = rows[0][1] if rows else 0
        teachings = rows[0][2] if rows else 0
        return jsonify({
            "used": analyses, "limit": FREE_DAILY_LIMIT,
            "remaining": max(0, FREE_DAILY_LIMIT - analyses),
            "f7_used": f7, "f7_remaining": max(0, FREE_DAILY_LIMIT - f7),
            "teachings_used": teachings, "teachings_remaining": max(0, FREE_DAILY_LIMIT - teachings),
            "tier": tier
        })
    except Exception as e:
        return safe_error(e)
def ai_check_scene_quality(image_b64):
    """Uses Claude to check if an image is a genuine outdoor Street-View-style
    scene, to keep the community library free of junk (selfies, screenshots
    of menus, blank/black images, memes, etc). Fails open (allows the
    upload) if the API key is missing or the check itself errors, so a
    Claude API outage never blocks legitimate F7 captures entirely."""
    import requests as req
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not anthropic_key:
        return True, "validation skipped"
    try:
        resp = req.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": anthropic_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            },
            json={
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 10,
                "messages": [{
                    "role": "user",
                    "content": [
                        {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": image_b64}},
                        {"type": "text", "text": "Is this a Google Street View scene of an outdoor real-world location? Reply only YES or NO."}
                    ]
                }]
            },
            timeout=10
        )
        answer = resp.json().get("content", [{}])[0].get("text", "").strip().upper()
        return answer.startswith("YES"), answer
    except Exception as e:
        print("Scene quality check error:", e)
        return True, "validation error — allowing"

@app.route("/scenes/validate", methods=["POST", "OPTIONS"])
def validate_scene():
    """Use Claude to check if image is a genuine Street View scene."""
    if request.method == "OPTIONS": return jsonify({}), 200
    image_b64 = (request.json or {}).get("image", "")
    if not image_b64:
        return jsonify({"valid": False, "reason": "no image"}), 400
    img_ok, img_err = validate_image_b64(image_b64)
    if not img_ok:
        return jsonify({"valid": False, "reason": img_err}), 400
    valid, reason = ai_check_scene_quality(image_b64)
    return jsonify({"valid": valid, "reason": reason})

@app.route("/scenes/upload", methods=["POST", "OPTIONS"])
def upload_scene():
    """Upload a scene image to R2 and record metadata in Supabase."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    image_b64 = d.get("image", "")
    country   = (d.get("country") or "").strip()
    state     = (d.get("state") or "").strip()
    lat       = d.get("lat")
    lng       = d.get("lng")
    token     = d.get("token", "")

    # Require authentication — previously an empty/missing token skipped
    # this check entirely, allowing fully anonymous, unlimited uploads.
    user_id, tier = get_user_from_token(token)
    if not user_id:
        return jsonify({"error": "Not logged in", "code": "auth"}), 401

    if rate_limited("scene_upload", str(user_id), max_attempts=30, window_seconds=60):
        return jsonify({"error": "Too many requests, please slow down."}), 429

    # If state is missing but we have coords and country is Australia, detect from coords
    if not state and country == 'Australia' and lat and lng:
        state = get_aus_state_from_coords(lat, lng)
        print(f"State from coords: {state}")

    if not image_b64 or not country:
        return jsonify({"error": "image and country required"}), 400
    img_ok, img_err = validate_image_b64(image_b64)
    if not img_ok:
        return jsonify({"error": img_err}), 400

    # AI quality check — keeps the community library free of selfies,
    # screenshots, blank/black frames, or other non-scene junk. Checked
    # before the daily quota is touched, so a rejected capture doesn't
    # cost the user one of their free uploads for the day.
    scene_ok, scene_reason = ai_check_scene_quality(image_b64)
    if not scene_ok:
        return jsonify({
            "error": "This doesn't look like a Street View scene, so it wasn't added to the library.",
            "code": "low_quality",
            "reason": scene_reason,
            "uploaded": False
        }), 400

    if tier != "pro":
        allowed, remaining = check_and_increment_usage(user_id, 'f7_captures')
        if not allowed:
            return jsonify({
                "error": "Daily F7 limit reached",
                "code": "limit",
                "message": f"You've used all {FREE_DAILY_LIMIT} free F7 captures for today. Upgrade to Pro for unlimited captures.",
                "uploaded": False
            }), 429

    if not SUPABASE_URL:
        return jsonify({"error": "Cloud storage not configured"}), 503

    region = classify_region(lat, lng, state)

    # Resolve contributor user id from token if provided
    contributor_id = None
    if token:
        try:
            conn = get_db()
            rows = conn.run("""SELECT u.id FROM users u JOIN sessions s ON s.user_id=u.id
                WHERE s.token=:t AND s.expires_at>NOW()""", t=token)
            conn.close()
            if rows: contributor_id = str(rows[0][0])
        except Exception:
            pass

    # Upload to R2
    r2_key = upload_to_r2(image_b64, country, state, region)
    if not r2_key:
        return jsonify({"error": "Upload failed"}), 500

    # Record in Supabase
    try:
        conn = get_db()
        conn.run("""INSERT INTO scenes (country, state, region, lat, lng, r2_key, contributor_user_id)
            VALUES (:country, :state, :region, :lat, :lng, :key, :cid)""",
            country=country, state=state, region=region,
            lat=lat, lng=lng, key=r2_key, cid=contributor_id)
        conn.close()
    except Exception as e:
        return safe_error(e)

    return jsonify({"uploaded": True, "region": region, "key": r2_key})

MAPILLARY_TOKEN = os.environ.get("MAPILLARY_ACCESS_TOKEN", "")

def fetch_mapillary_image(lat, lng, radius_m=2000):
    """Fetches a real street-level photo near the given coordinates from
    Mapillary's free, worldwide crowdsourced imagery API. Used as a fallback
    when there's no community-uploaded scene near a guess location yet —
    means a 'where you guessed' photo can be genuinely accurate (showing
    Sydney for a Sydney guess) instead of misleadingly using whatever
    same-state photo happens to exist in the community library, or showing
    nothing at all. Fails silently (returns None) if no token is configured
    or nothing is found nearby, so this never blocks the rest of the
    teaching guide from working."""
    if not MAPILLARY_TOKEN or lat is None or lng is None:
        return None
    try:
        import requests as req
        resp = req.get(
            "https://graph.mapillary.com/images",
            params={
                "access_token": MAPILLARY_TOKEN,
                "fields": "thumb_1024_url",
                "closeto": f"{lng},{lat}",
                "radius": radius_m,
                "limit": 1
            },
            timeout=8
        )
        data = resp.json().get("data", [])
        if not data:
            return None
        img_url = data[0].get("thumb_1024_url")
        if not img_url:
            return None
        img_resp = req.get(img_url, timeout=10)
        if img_resp.status_code != 200:
            return None
        return base64.b64encode(img_resp.content).decode()
    except Exception as e:
        print("Mapillary fetch error:", e)
        return None

@app.route("/scenes/refs", methods=["POST", "OPTIONS"])
def get_refs():
    """Get up to N reference scene images for a given location. Prefers
    community-uploaded scenes near the given lat/lng (genuinely close, not
    just 'somewhere in the same state'); falls back to a broader state/
    country match if nothing nearby exists; falls back to a real Mapillary
    street-level photo near the exact coordinates if the community library
    has nothing useful for this area at all."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    state   = (d.get("state") or "").strip()
    country = (d.get("country") or "").strip()
    region  = (d.get("region") or "").strip()
    lat     = d.get("lat")
    lng     = d.get("lng")
    limit   = min(int(d.get("limit", 5)), 8)

    if not state and not country:
        return jsonify({"error": "state or country required"}), 400

    try:
        conn = get_db()
        rows = []

        # 1. Try proximity match first, if we have coordinates to work with —
        # pull a generous candidate pool scoped to the right state/country,
        # then rank by actual distance in Python (avoids needing a Postgres
        # geo extension for a feature at this scale).
        if lat is not None and lng is not None:
            scope_clause = "state ILIKE :state" if state else "country ILIKE :country"
            scope_val = state if state else country
            candidates = conn.run(f"""
                SELECT r2_key, region, quality_score, lat, lng FROM scenes
                WHERE {scope_clause} AND lat IS NOT NULL AND lng IS NOT NULL
                ORDER BY uploaded_at DESC LIMIT 200""",
                **{("state" if state else "country"): scope_val})

            def haversine_km(lat1, lng1, lat2, lng2):
                R = 6371
                p1, p2 = math.radians(lat1), math.radians(lat2)
                dphi = math.radians(lat2 - lat1)
                dlmb = math.radians(lng2 - lng1)
                a = math.sin(dphi/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dlmb/2)**2
                return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

            scored = sorted(
                ((haversine_km(lat, lng, r[3], r[4]), r) for r in candidates),
                key=lambda x: x[0]
            )
            # Only trust "nearby" matches within 300km — beyond that fall
            # through to a broader match or Mapillary. 300km is generous
            # but needed for large states like SA/WA/QLD where community
            # uploads near the round's actual location can still be hundreds
            # of km from where the player guessed.
            nearby = [r for dist, r in scored if dist <= 300][:limit]
            rows = [(r[0], r[1], r[2]) for r in nearby]

        # 2. Fall back to the original broad state/region/country match if
        # no nearby community scene was found.
        if not rows:
            if state and region:
                rows = conn.run("""
                    SELECT r2_key, region, quality_score FROM scenes
                    WHERE state ILIKE :state
                    ORDER BY (region = :region) DESC, quality_score DESC, uploaded_at DESC
                    LIMIT :limit""",
                    state=state, region=region, limit=limit)
            elif state:
                rows = conn.run("""
                    SELECT r2_key, region, quality_score FROM scenes
                    WHERE state ILIKE :state
                    ORDER BY quality_score DESC, uploaded_at DESC
                    LIMIT :limit""",
                    state=state, limit=limit)
            else:
                rows = conn.run("""
                    SELECT r2_key, region, quality_score FROM scenes
                    WHERE country ILIKE :country
                    ORDER BY quality_score DESC, uploaded_at DESC
                    LIMIT :limit""",
                    country=country, limit=limit)

        # Increment times_used for returned scenes
        keys = [r[0] for r in rows]
        if keys:
            for key in keys:
                conn.run("UPDATE scenes SET times_used = times_used + 1 WHERE r2_key = :k", k=key)
        conn.close()
    except Exception as e:
        return safe_error(e)

    images = []
    for r2_key, region_name, score in rows:
        b64 = get_r2_image_b64(r2_key)
        if b64:
            images.append({"b64": b64, "region": region_name, "quality_score": score, "source": "community"})

    # 3. Still nothing? Try a real photo from Mapillary near the exact
    # coordinates, so the guide can show something genuinely accurate
    # instead of a misleading same-state photo or no photo at all.
    if not images and lat is not None and lng is not None:
        mapillary_b64 = fetch_mapillary_image(lat, lng)
        if mapillary_b64:
            images.append({"b64": mapillary_b64, "region": region or state, "quality_score": 0, "source": "mapillary"})

    return jsonify({"images": images, "count": len(images)})

@app.route("/scenes/count", methods=["GET"])
def scene_count():
    """Return total scene count per state for stats."""
    try:
        conn = get_db()
        rows = conn.run("SELECT state, COUNT(*) FROM scenes GROUP BY state ORDER BY COUNT(*) DESC")
        conn.close()
        return jsonify({"counts": [{"state": r[0], "count": r[1]} for r in rows]})
    except Exception as e:
        return safe_error(e)

# ── Admin ─────────────────────────────────────────────────
def require_admin():
    """Returns (ok, error_response). Requires both the ADMIN_KEY (via X-Admin-Key
    header) AND a valid session token (via X-Admin-Token header) belonging to a
    user with is_admin=TRUE. Keeping these out of the URL/body means they never
    end up in server access logs or browser history."""
    if rate_limited("admin_check", client_ip(), max_attempts=60, window_seconds=60):
        return False, (jsonify({"error":"Too many requests"}), 429)
    if not ADMIN_KEY or request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return False, (jsonify({"error":"Forbidden"}), 403)
    admin_token = request.headers.get("X-Admin-Token", "")
    if not admin_token:
        return False, (jsonify({"error":"Admin login required"}), 401)
    try:
        conn = get_db()
        rows = conn.run("""SELECT u.is_admin FROM users u
            JOIN sessions s ON s.user_id=u.id
            WHERE s.token=:t AND s.expires_at>NOW()""", t=admin_token)
        conn.close()
    except Exception as e:
        print("Server error:", repr(e))
        return False, (jsonify({"error": "Something went wrong"}), 500)
    if not rows or not rows[0][0]:
        return False, (jsonify({"error":"Account is not an admin"}), 403)
    return True, None

@app.route("/admin/login", methods=["POST","OPTIONS"])
def admin_login():
    """Separate from /auth/login: verifies admin_key + credentials + is_admin in one step,
    and returns a session token for use as the X-Admin-Token header on every other /admin/* call."""
    if request.method == "OPTIONS": return jsonify({}), 200
    if rate_limited("admin_login_ip", client_ip(), max_attempts=10, window_seconds=600):
        return jsonify({"error": "Too many login attempts. Try again later."}), 429
    d = request.json or {}
    if not ADMIN_KEY or request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return jsonify({"error":"Forbidden"}),403
    email    = d.get("email","").strip().lower()
    password = d.get("password","")
    totp_code = d.get("totp_code", "").strip()
    if rate_limited("admin_login_email", email, max_attempts=6, window_seconds=600):
        return jsonify({"error": "Too many login attempts for this account. Try again later."}), 429
    try:
        conn = get_db()
        rows = conn.run("SELECT id,username,email,is_admin,password,totp_enabled,totp_secret FROM users WHERE email=:e", e=email)
        if not rows or not verify_password(rows[0][4], password) or not rows[0][3]:
            conn.close(); return jsonify({"error":"Invalid credentials or not an admin"}),403
        totp_enabled, totp_secret = rows[0][5], rows[0][6]
        if totp_enabled:
            if not totp_code:
                conn.close(); return jsonify({"error": "2FA code required", "code": "totp_required"}), 401
            if not pyotp.TOTP(totp_secret).verify(totp_code, valid_window=1):
                conn.close(); return jsonify({"error": "Invalid 2FA code", "code": "totp_invalid"}), 401
        user_id = rows[0][0]
        token = secrets.token_urlsafe(32)
        conn.run("INSERT INTO sessions (token,user_id) VALUES (:t,:uid)", t=token, uid=user_id)
        conn.close()
        return jsonify({"admin_token": token, "username": rows[0][1], "email": rows[0][2]})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/toggle_disabled", methods=["POST","OPTIONS"])
def admin_toggle_disabled():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    ok, err = require_admin()
    if not ok: return err
    user_id = d.get("user_id")
    disabled = d.get("disabled", True)
    if not user_id:
        return jsonify({"error":"user_id required"}),400
    try:
        conn = get_db()
        conn.run("UPDATE users SET disabled=:d WHERE id=:uid", d=disabled, uid=user_id)
        if disabled:
            conn.run("DELETE FROM sessions WHERE user_id=:uid", uid=user_id)
        conn.close()
        return jsonify({"success": True, "disabled": disabled})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/ban_user", methods=["POST","OPTIONS"])
def admin_ban_user():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    ok, err = require_admin()
    if not ok: return err
    user_id = d.get("user_id")
    duration = d.get("duration")  # '1d','3d','1w','1m','permanent','unban'
    reason = d.get("reason", "")
    if not user_id:
        return jsonify({"error":"user_id required"}),400
    try:
        conn = get_db()
        if duration == "unban":
            conn.run("UPDATE users SET banned_until=NULL, ban_reason=NULL WHERE id=:uid", uid=user_id)
        else:
            interval_map = {
                "1d": "1 day", "3d": "3 days", "1w": "7 days",
                "1m": "30 days", "permanent": "100 years"
            }
            interval = interval_map.get(duration, "1 day")
            conn.run(f"""UPDATE users SET banned_until=NOW() + INTERVAL '{interval}', ban_reason=:reason
                WHERE id=:uid""", uid=user_id, reason=reason)
            # Also kill their active sessions immediately
            conn.run("DELETE FROM sessions WHERE user_id=:uid", uid=user_id)
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/delete_user", methods=["POST","OPTIONS"])
def admin_delete_user():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    ok, err = require_admin()
    if not ok: return err
    user_id = d.get("user_id")
    if not user_id:
        return jsonify({"error":"user_id required"}),400
    try:
        conn = get_db()
        conn.run("DELETE FROM usage WHERE user_id=:uid", uid=user_id)
        conn.run("DELETE FROM sessions WHERE user_id=:uid", uid=user_id)
        conn.run("DELETE FROM users WHERE id=:uid", uid=user_id)
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/reset_usage", methods=["POST","OPTIONS"])
def admin_reset_usage():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    ok, err = require_admin()
    if not ok: return err
    user_id = d.get("user_id")
    try:
        conn = get_db()
        if user_id:
            conn.run("DELETE FROM usage WHERE user_id=:uid AND date=CURRENT_DATE", uid=user_id)
        else:
            conn.run("DELETE FROM usage WHERE date=CURRENT_DATE")
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/set_tier", methods=["POST","OPTIONS"])
def admin_set_tier():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    ok, err = require_admin()
    if not ok: return err
    user_id = d.get("user_id")
    email   = d.get("email","").strip().lower()
    tier    = d.get("tier","free")
    if tier not in ("free","pro","beta"): return jsonify({"error":"Invalid tier"}),400
    try:
        conn = get_db()
        if user_id:
            rows = conn.run("UPDATE users SET tier=:tier WHERE id=:uid RETURNING username,email,tier",
                            tier=tier, uid=user_id)
        else:
            rows = conn.run("UPDATE users SET tier=:tier WHERE email=:e RETURNING username,email,tier",
                            tier=tier, e=email)
        conn.close()
        if not rows: return jsonify({"error":"User not found"}),404
        return jsonify({"success": True, "updated":{"username":rows[0][0],"email":rows[0][1],"tier":rows[0][2]}})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/stats", methods=["GET","OPTIONS"])
def admin_stats():
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    try:
        conn = get_db()
        users     = conn.run("SELECT COUNT(*) FROM users")[0][0]
        pro_users = conn.run("SELECT COUNT(*) FROM users WHERE tier='pro'")[0][0]
        free_users= conn.run("SELECT COUNT(*) FROM users WHERE tier='free'")[0][0]
        scenes    = conn.run("SELECT COUNT(*) FROM scenes")[0][0]
        new_today = conn.run("SELECT COUNT(*) FROM users WHERE created_at::date = CURRENT_DATE")[0][0]
        usage_today = conn.run("""
            SELECT u.username, u.tier, us.f7_captures, us.teachings, us.analyses
            FROM usage us JOIN users u ON u.id = us.user_id
            WHERE us.date = CURRENT_DATE ORDER BY us.teachings DESC""")
        conn.close()
        return jsonify({
            "total_users": users, "pro_users": pro_users,
            "free_users": free_users, "scenes": scenes,
            "new_today": new_today,
            "usage_today": [{"username":r[0],"tier":r[1],"f7":r[2],"guides":r[3],"analyses":r[4]} for r in usage_today]
        })
    except Exception as e:
        return safe_error(e)

@app.route("/admin/users", methods=["GET","OPTIONS"])
def admin_users():
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    try:
        conn  = get_db()
        rows  = conn.run("SELECT id,username,email,tier,created_at,last_login,banned_until,ban_reason,disabled,is_admin,email_verified FROM users ORDER BY created_at DESC")
        conn.close()
        users = [{"id":r[0],"username":r[1],"email":r[2],"tier":r[3],
                  "created_at":str(r[4]),"last_login":str(r[5]),
                  "banned_until": str(r[6]) if r[6] else None,
                  "ban_reason": r[7], "disabled": bool(r[8]),
                  "is_admin": bool(r[9]), "email_verified": bool(r[10])} for r in rows]
        return jsonify({"users":users,"count":len(users)})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/set_admin", methods=["POST","OPTIONS"])
def admin_set_admin():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    ok, err = require_admin()
    if not ok: return err
    user_id  = d.get("user_id")
    is_admin = bool(d.get("is_admin", True))
    if not user_id:
        return jsonify({"error":"user_id required"}),400
    try:
        conn = get_db()
        # Prevent removing the last remaining admin so the panel never locks everyone out
        if not is_admin:
            count = conn.run("SELECT COUNT(*) FROM users WHERE is_admin=TRUE")[0][0]
            target = conn.run("SELECT is_admin FROM users WHERE id=:uid", uid=user_id)
            if target and target[0][0] and count <= 1:
                conn.close()
                return jsonify({"error":"Cannot remove the last remaining admin"}),400
        rows = conn.run("UPDATE users SET is_admin=:a WHERE id=:uid RETURNING username,email,is_admin",
                        a=is_admin, uid=user_id)
        conn.close()
        if not rows: return jsonify({"error":"User not found"}),404
        return jsonify({"success": True, "updated":{"username":rows[0][0],"email":rows[0][1],"is_admin":bool(rows[0][2])}})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/resend_verification", methods=["POST","OPTIONS"])
def admin_resend_verification():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    ok, err = require_admin()
    if not ok: return err
    user_id = d.get("user_id")
    if not user_id:
        return jsonify({"error":"user_id required"}),400
    try:
        conn = get_db()
        rows = conn.run("SELECT username,email,email_verified FROM users WHERE id=:uid", uid=user_id)
        if not rows:
            conn.close(); return jsonify({"error":"User not found"}),404
        username, email, verified = rows[0]
        if verified:
            conn.close(); return jsonify({"error":"User is already verified"}),400
        new_code = str(secrets.randbelow(900000) + 100000)
        conn.run("UPDATE users SET verify_code=:c, verify_expires=NOW() + INTERVAL '15 minutes' WHERE id=:uid",
                  c=new_code, uid=user_id)
        conn.close()
        send_verification_email(email, username, new_code)
        return jsonify({"success": True})
    except Exception as e:
        return safe_error(e)

# ── Stripe ────────────────────────────────────────────────
@app.route("/stripe/create-checkout", methods=["POST", "OPTIONS"])
def create_checkout():
    if request.method == "OPTIONS": return jsonify({}), 200
    if not stripe.api_key:
        return jsonify({"error": "Stripe not configured"}), 500
    d = request.json or {}
    token = d.get("token", "")
    try:
        conn = get_db()
        rows = conn.run("""SELECT u.id, u.email, u.username FROM users u
            JOIN sessions s ON s.user_id = u.id
            WHERE s.token = :t AND s.expires_at > NOW()""", t=token)
        conn.close()
        if not rows: return jsonify({"error": "Invalid token"}), 401
        user_id, email, username = rows[0][0], rows[0][1], rows[0][2]
    except Exception as e:
        return safe_error(e)
    if not STRIPE_PRO_PRICE_ID:
        return jsonify({"error": "not configured"}), 503
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card", "link"],
            payment_method_options={"card": {"request_three_d_secure": "automatic"}},
            mode="subscription",
            customer_email=email,
            line_items=[{"price": STRIPE_PRO_PRICE_ID, "quantity": 1}],
            success_url=FRONTEND_URL + "?upgrade=success&session_id={CHECKOUT_SESSION_ID}",
            cancel_url=FRONTEND_URL + "?upgrade=cancelled",
            metadata={"user_id": str(user_id), "username": username}
        )
        return jsonify({"url": session.url})
    except stripe.error.AuthenticationError:
        return jsonify({"error": "Stripe authentication failed — check STRIPE_SECRET_KEY"}), 503
    except Exception as e:
        return safe_error(e)

@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data()
    sig     = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        print("Stripe webhook signature error:", repr(e))
        return jsonify({"error": "Invalid signature"}), 400
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        user_id = session.get("metadata", {}).get("user_id")
        if user_id:
            try:
                conn = get_db()
                conn.run("UPDATE users SET tier = 'pro' WHERE id = :uid", uid=int(user_id))
                conn.close()
                print(f"Upgraded user {user_id} to pro")
            except Exception as e:
                print(f"Webhook DB error: {e}")
    if event["type"] in ("customer.subscription.deleted", "customer.subscription.paused"):
        customer_id = event["data"]["object"].get("customer")
        if customer_id:
            try:
                customer = stripe.Customer.retrieve(customer_id)
                email = customer.get("email", "")
                conn  = get_db()
                conn.run("UPDATE users SET tier = 'free' WHERE email = :e", e=email)
                conn.close()
                print(f"Downgraded {email} to free")
            except Exception as e:
                print(f"Webhook downgrade error: {e}")
    return jsonify({"received": True})

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)), debug=False)
