"""
GeoAnalyzerX Platform API — v2.0 with Cloud Scene Library (Cloudflare R2)
"""
from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib, os, secrets, uuid, base64, io, time, threading, re, math, queue, json as _json, random, datetime
import pg8000.native
from urllib.parse import urlparse

app = Flask(__name__)
# Caps total request body size (generous for a base64-encoded screenshot,
# but blocks someone sending an enormous payload to waste server resources,
# inflate Supabase storage costs, or rack up Claude API costs).
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB for guide saves with images
CORS(app, origins=[
    "https://geoanalyzerx.net",
    "https://www.geoanalyzerx.net",
    re.compile(r"^chrome-extension://.*$"),
    re.compile(r"^moz-extension://.*$"),
], supports_credentials=True, allow_headers=["Content-Type", "X-Admin-Key", "X-Admin-Token"])

# ── SSE admin event bus ───────────────────────────────────
# Each connected admin panel gets its own Queue. When log_event() fires,
# it pushes the event to every active queue so the browser receives it
# instantly via the persistent SSE connection rather than polling.
_sse_subscribers = []
_sse_lock = threading.Lock()

def _sse_push(event_dict):
    """Push an event to all connected admin SSE clients. Dead connections
    are pruned automatically when their queue.put() raises (queue full)."""
    with _sse_lock:
        dead = []
        for q in _sse_subscribers:
            try:
                q.put_nowait(event_dict)
            except Exception:
                dead.append(q)
        for q in dead:
            _sse_subscribers.remove(q)

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

# ── Twilio (phone verification) ──────────────────────────────
try:
    from twilio.rest import Client as TwilioClient
    from twilio.base.exceptions import TwilioRestException
except ImportError:
    TwilioClient = None
    TwilioRestException = Exception
    print("twilio package not installed — run: pip install twilio")

TWILIO_ACCOUNT_SID        = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN         = os.environ.get("TWILIO_AUTH_TOKEN", "")
TWILIO_VERIFY_SERVICE_SID = os.environ.get("TWILIO_VERIFY_SERVICE_SID", "")

_twilio_client = None
if TwilioClient and TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
    _twilio_client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# If Twilio isn't fully configured, phone verification is treated as
# not-required anywhere below — this prevents locking every signup out
# behind a code that can never actually be sent. Once the env vars are
# set, enforcement turns on automatically without a code change.
TWILIO_CONFIGURED = bool(_twilio_client and TWILIO_VERIFY_SERVICE_SID)
print(f"Twilio configured: {'YES' if TWILIO_CONFIGURED else 'MISSING (phone verification disabled)'}")

def is_valid_e164(phone):
    """Basic E.164 check: + followed by 7-15 digits, no spaces/dashes."""
    return bool(re.match(r'^\+[1-9]\d{6,14}$', phone or ""))

def send_phone_verification(phone_number):
    """Sends an SMS verification code via Twilio Verify. Returns True/False."""
    if not TWILIO_CONFIGURED:
        print("Twilio not configured, skipping SMS send")
        return False
    try:
        _twilio_client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID) \
            .verifications.create(to=phone_number, channel="sms")
        return True
    except TwilioRestException as e:
        print("Twilio send error:", e)
        return False

def check_phone_verification(phone_number, code):
    """Checks a submitted code against Twilio Verify. Returns True/False."""
    if not TWILIO_CONFIGURED:
        return False
    try:
        check = _twilio_client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID) \
            .verification_checks.create(to=phone_number, code=code)
        return check.status == "approved"
    except TwilioRestException as e:
        print("Twilio check error:", e)
        return False


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
            conn.run("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_number TEXT")
            conn.run("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified BOOLEAN DEFAULT FALSE")
            conn.run("ALTER TABLE users ADD COLUMN IF NOT EXISTS active_badge_country TEXT")
            conn.run("ALTER TABLE scenes ADD COLUMN IF NOT EXISTS quality_checked_at TIMESTAMPTZ")
            conn.run("ALTER TABLE scenes ADD COLUMN IF NOT EXISTS quality_reason TEXT")
            conn.run("ALTER TABLE scenes ADD COLUMN IF NOT EXISTS camera_generation TEXT")
        except: pass
        try:
            conn.run("ALTER TABLE users ADD CONSTRAINT users_phone_number_key UNIQUE (phone_number)")
        except: pass
        # Grandfather accounts that predate the phone_number column — any row
        # with phone_number IS NULL can only be a legacy account, since every
        # registration after this feature shipped always sets one. Without
        # this, those accounts would be locked out permanently (can't verify
        # a number they don't have, can't log in to add one). Safe to run on
        # every startup: has zero effect once all legacy rows are caught up.
        try:
            conn.run("UPDATE users SET phone_verified=TRUE WHERE phone_number IS NULL AND phone_verified=FALSE")
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
        conn.run("""CREATE TABLE IF NOT EXISTS chat_logs (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            user_id INT REFERENCES users(id),
            username TEXT,
            correct_location TEXT,
            guessed_location TEXT,
            user_message TEXT NOT NULL,
            ai_reply TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW())""")
        conn.run("""CREATE TABLE IF NOT EXISTS activity_logs (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            event_type TEXT NOT NULL,
            user_id INT,
            username TEXT,
            detail TEXT,
            ip TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW())""")
        conn.run("CREATE INDEX IF NOT EXISTS idx_activity_logs_type ON activity_logs(event_type)")
        conn.run("CREATE INDEX IF NOT EXISTS idx_activity_logs_user ON activity_logs(user_id)")
        conn.run("CREATE INDEX IF NOT EXISTS idx_activity_logs_time ON activity_logs(created_at DESC)")
        conn.run("""CREATE TABLE IF NOT EXISTS country_metas (
            iso TEXT PRIMARY KEY,
            country TEXT,
            content TEXT,
            source TEXT DEFAULT 'ai',
            last_edited_by TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW())""")
        conn.run("""CREATE TABLE IF NOT EXISTS guess_results (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            user_id INT NOT NULL,
            country TEXT NOT NULL,
            correct_region TEXT,
            guessed_region TEXT,
            is_correct BOOLEAN NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW())""")
        conn.run("CREATE INDEX IF NOT EXISTS idx_guess_results_user ON guess_results(user_id)")
        conn.run("CREATE INDEX IF NOT EXISTS idx_guess_results_country ON guess_results(user_id, country)")
        conn.run("""CREATE TABLE IF NOT EXISTS form_submissions (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            user_id INT,
            form_type TEXT NOT NULL,
            name TEXT,
            email TEXT,
            message TEXT,
            extra TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW())""")
        conn.run("CREATE INDEX IF NOT EXISTS idx_form_submissions_type ON form_submissions(form_type)")
        conn.run("""CREATE TABLE IF NOT EXISTS camera_quiz_images (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            image_url TEXT NOT NULL,
            correct_gen TEXT NOT NULL,
            uploaded_by TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW())""")
        conn.run("""CREATE TABLE IF NOT EXISTS photo_quiz_images (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            quiz_type TEXT NOT NULL,
            image_url TEXT NOT NULL,
            correct_country TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW())""")
        conn.run("CREATE INDEX IF NOT EXISTS idx_photo_quiz_type ON photo_quiz_images(quiz_type)")
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
    """Logs the full exception server-side and returns a generic message to
    clients. For admin endpoints, includes the actual error to aid debugging."""
    import traceback
    tb = traceback.format_exc()
    print("Server error:", repr(e))
    print(tb)
    # Include actual error in response for easier debugging
    return jsonify({"error": f"Server error: {repr(e)}"}), 500

def log_event(event_type, user_id=None, username=None, detail=None, ip=None):
    """Fire-and-forget activity logger. Never raises — a logging failure
    should never break the actual request."""
    try:
        conn = get_db()
        conn.run("""INSERT INTO activity_logs (event_type, user_id, username, detail, ip)
            VALUES (:t, :uid, :un, :d, :ip)""",
            t=event_type, uid=user_id, un=username, d=detail, ip=ip)
        conn.close()
    except Exception as le:
        print("log_event error:", le)
    # Push instantly to any connected admin SSE clients
    try:
        from datetime import datetime
        _sse_push({
            "event_type": event_type,
            "user_id": user_id,
            "username": username,
            "detail": detail,
            "ip": ip,
            "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M")
        })
    except Exception:
        pass

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
        import unicodedata
        image_bytes = base64.b64decode(image_b64)

        def safe_segment(s, default):
            # Strip diacritics (e.g. the macron in "Manawatū-Whanganui")
            # before using a value as a raw URL path segment. Without this,
            # region/state names with accented characters could silently
            # fail to upload, or land under an inconsistently-encoded path
            # that never shows up as a clean matching folder — which is
            # exactly why Manawatū-Whanganui was missing while every other
            # (plain-ASCII) NZ region worked fine.
            s = s or default
            s = unicodedata.normalize('NFKD', s).encode('ascii', 'ignore').decode('ascii')
            return s or default

        key = f"{safe_segment(country,'unknown')}/{safe_segment(state,'unknown')}/{safe_segment(region,'central')}/{uuid.uuid4()}.jpg"
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
    username     = d.get("username","").strip()
    email        = d.get("email","").strip().lower()
    password     = d.get("password","")
    phone_number = d.get("phone_number","").strip()
    if rate_limited("register_ip", client_ip(), max_attempts=10, window_seconds=3600):
        return jsonify({"error": "Too many accounts created from this network. Try again later."}), 429
    if len(username)<3: return jsonify({"error":"Username must be at least 3 characters"}),400
    if len(username)>32: return jsonify({"error":"Username must be 32 characters or fewer"}),400
    if not re.match(r'^[A-Za-z0-9_]+$', username):
        return jsonify({"error":"Username can only contain letters, numbers, and underscores"}),400
    if "@" not in email: return jsonify({"error":"Invalid email"}),400
    if len(password)<6: return jsonify({"error":"Password must be at least 6 characters"}),400
    if not is_valid_e164(phone_number):
        return jsonify({"error":"Enter a valid phone number in international format, e.g. +61412345678"}),400
    try:
        conn  = get_db()
        verify_code = str(secrets.randbelow(900000) + 100000)  # 6-digit code
        # If Twilio isn't configured, don't gate the account behind a code
        # that can never arrive — mark phone as verified immediately instead.
        initial_phone_verified = not TWILIO_CONFIGURED
        rows  = conn.run(
            """INSERT INTO users (username,email,password,verify_code,verify_expires,phone_number,phone_verified)
               VALUES (:u,:e,:p,:c,NOW() + INTERVAL '15 minutes',:ph,:pv)
               RETURNING id,username,email,tier,phone_number,phone_verified""",
            u=username, e=email, p=hash_password(password), c=verify_code,
            ph=phone_number, pv=initial_phone_verified)
        user  = {"id":rows[0][0],"username":rows[0][1],"email":rows[0][2],"tier":rows[0][3],
                  "phone_number":rows[0][4],"phone_verified":bool(rows[0][5])}
        token = secrets.token_urlsafe(32)
        conn.run("INSERT INTO sessions (token,user_id) VALUES (:t,:uid)", t=token, uid=user["id"])
        conn.close()
        send_verification_email(email, username, verify_code)
        if TWILIO_CONFIGURED:
            send_phone_verification(phone_number)
        log_event("register", user_id=user["id"], username=username, detail=f"email={email}", ip=client_ip())
        return jsonify({"token":token,"user":user,"needs_verification":True}), 201
    except Exception as e:
        err = str(e)
        if "unique" in err.lower():
            if "phone_number" in err.lower():
                return jsonify({"error":"This phone number is already registered to another account"}),409
            return jsonify({"error":"Username or email already taken"}),409
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
        rows = conn.run("""SELECT u.id, u.verify_code, u.verify_expires, u.email_verified, u.phone_verified, u.username
            FROM users u JOIN sessions s ON s.user_id=u.id
            WHERE s.token=:t""", t=token)
        if not rows:
            conn.close(); return jsonify({"error": "Invalid session"}), 401
        user_id, stored_code, expires, already_verified, phone_verified, username = rows[0]
        if already_verified:
            conn.close(); return jsonify({"success": True, "already_verified": True, "needs_phone_verification": not phone_verified})
        if not stored_code or stored_code != code:
            conn.close(); return jsonify({"error": "Incorrect code"}), 400
        if expires and str(expires) < str(conn.run("SELECT NOW()")[0][0]):
            conn.close(); return jsonify({"error": "Code expired, please request a new one"}), 400
        conn.run("UPDATE users SET email_verified=TRUE, verify_code=NULL WHERE id=:uid", uid=user_id)
        conn.close()
        log_event("email_verified", user_id=user_id, username=username, ip=client_ip())
        return jsonify({"success": True, "needs_phone_verification": not phone_verified})
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

@app.route("/auth/verify_phone", methods=["POST", "OPTIONS"])
def verify_phone():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token = d.get("token", "")
    code  = d.get("code", "").strip()
    if not token or not code:
        return jsonify({"error": "Token and code required"}), 400
    if rate_limited("verify_phone", token, max_attempts=8, window_seconds=900):
        return jsonify({"error": "Too many attempts. Please request a new code and try again shortly."}), 429
    try:
        conn = get_db()
        rows = conn.run("""SELECT u.id, u.phone_number, u.phone_verified, u.username
            FROM users u JOIN sessions s ON s.user_id=u.id
            WHERE s.token=:t""", t=token)
        if not rows:
            conn.close(); return jsonify({"error": "Invalid session"}), 401
        user_id, phone_number, already_verified, username = rows[0]
        if already_verified:
            conn.close(); return jsonify({"success": True, "already_verified": True})
        if not phone_number:
            conn.close(); return jsonify({"error": "No phone number on file for this account"}), 400
        if not check_phone_verification(phone_number, code):
            conn.close(); return jsonify({"error": "Incorrect or expired code"}), 400
        conn.run("UPDATE users SET phone_verified=TRUE WHERE id=:uid", uid=user_id)
        conn.close()
        log_event("phone_verified", user_id=user_id, username=username, ip=client_ip())
        return jsonify({"success": True})
    except Exception as e:
        return safe_error(e)

@app.route("/auth/resend_phone_code", methods=["POST", "OPTIONS"])
def resend_phone_code():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token = d.get("token", "")
    if not token:
        return jsonify({"error": "Invalid session"}), 401
    if rate_limited("resend_phone_code", token, max_attempts=3, window_seconds=600):
        return jsonify({"error": "Please wait a few minutes before requesting another code."}), 429
    try:
        conn = get_db()
        rows = conn.run("""SELECT u.id, u.phone_number, u.phone_verified FROM users u
            JOIN sessions s ON s.user_id=u.id WHERE s.token=:t""", t=token)
        if not rows:
            conn.close(); return jsonify({"error": "Invalid session"}), 401
        user_id, phone_number, verified = rows[0]
        conn.close()
        if verified:
            return jsonify({"error": "Already verified"}), 400
        if not phone_number:
            return jsonify({"error": "No phone number on file for this account"}), 400
        if not send_phone_verification(phone_number):
            return jsonify({"error": "Couldn't send SMS right now. Please try again shortly."}), 502
        return jsonify({"success": True})
    except Exception as e:
        return safe_error(e)

@app.route("/auth/request_phone_verification", methods=["POST", "OPTIONS"])
def request_phone_verification():
    """Mirrors request_verification() but for the phone-verification step —
    for accounts that verified email but never finished phone verification
    and are now stuck with no way back into the code-entry screen."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    email    = d.get("email","").strip().lower()
    password = d.get("password","")
    if rate_limited("request_phone_verification_ip", client_ip(), max_attempts=10, window_seconds=600):
        return jsonify({"error": "Too many attempts. Try again later."}), 429
    if email and rate_limited("request_phone_verification_email", email, max_attempts=5, window_seconds=600):
        return jsonify({"error": "Too many attempts for this account. Try again later."}), 429
    try:
        conn = get_db()
        rows = conn.run("""SELECT id,username,email,tier,password,email_verified,phone_number,phone_verified
            FROM users WHERE email=:e""", e=email)
        if not rows or not verify_password(rows[0][4], password):
            conn.close(); return jsonify({"error":"Invalid email or password"}),401
        user_id, username, email, tier, _, email_verified, phone_number, phone_verified = rows[0]
        if not email_verified:
            conn.close(); return jsonify({"error":"Please verify your email first.", "code":"unverified"}), 400
        if phone_verified:
            conn.close(); return jsonify({"error":"This account is already verified. Try signing in normally."}), 400
        if not phone_number:
            conn.close(); return jsonify({"error":"No phone number on file for this account."}), 400
        token = secrets.token_urlsafe(32)
        conn.run("INSERT INTO sessions (token,user_id) VALUES (:t,:uid)", t=token, uid=user_id)
        conn.close()
        send_phone_verification(phone_number)
        user = {"id": user_id, "username": username, "email": email, "tier": tier}
        return jsonify({"token": token, "user": user, "needs_phone_verification": True})
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
        log_event("rate_limit_login", detail=f"ip={client_ip()} email={email}", ip=client_ip())
        return jsonify({"error": "Too many login attempts from this network. Try again in a few minutes."}), 429
    if email and rate_limited("login_email", email, max_attempts=8, window_seconds=600):
        log_event("rate_limit_login", detail=f"email={email}", ip=client_ip())
        return jsonify({"error": "Too many login attempts for this account. Try again in a few minutes."}), 429

    try:
        conn = get_db()
        rows = conn.run("""SELECT id,username,email,tier,banned_until,ban_reason,disabled,email_verified,
                            password,totp_enabled,totp_secret,phone_verified,phone_number,active_badge_country FROM users WHERE email=:e""", e=email)
        if not rows or not verify_password(rows[0][8], password):
            conn.close()
            log_event("login_failed", detail=f"email={email}", ip=client_ip())
            return jsonify({"error":"Invalid email or password"}),401
        # Transparently upgrade legacy SHA-256 hashes to salted hashes on successful login
        if not rows[0][8].startswith(("scrypt:", "pbkdf2:")):
            conn.run("UPDATE users SET password=:p WHERE id=:uid", p=hash_password(password), uid=rows[0][0])
        if rows[0][6]:
            conn.close()
            return jsonify({"error": "Account disabled", "code": "disabled"}), 403
        if not rows[0][7]:
            conn.close()
            return jsonify({"error": "Please verify your email before logging in", "code": "unverified"}), 403
        if TWILIO_CONFIGURED and rows[0][12] and not rows[0][11]:
            conn.close()
            return jsonify({"error": "Please verify your phone number before logging in", "code": "phone_unverified"}), 403
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
        user  = {"id":rows[0][0],"username":rows[0][1],"email":rows[0][2],"tier":rows[0][3],
                  "phone_number":rows[0][12],"phone_verified":bool(rows[0][11]),"active_badge_country":rows[0][13]}
        token = secrets.token_urlsafe(32)
        conn.run("INSERT INTO sessions (token,user_id) VALUES (:t,:uid)", t=token, uid=user["id"])
        conn.run("UPDATE users SET last_login=NOW() WHERE id=:uid", uid=user["id"])
        conn.close()
        log_event("login", user_id=user["id"], username=user["username"], detail=f"tier={user['tier']}", ip=client_ip())
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
        rows = conn.run("SELECT user_id FROM sessions WHERE token=:t", t=token)
        uid = rows[0][0] if rows else None
        conn.run("DELETE FROM sessions WHERE token=:t", t=token)
        conn.close()
        log_event("logout", user_id=uid, ip=client_ip())
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
        rows = conn.run("""SELECT u.id,u.username,u.email,u.tier,u.created_at,u.banned_until,u.ban_reason,u.email_verified,u.phone_verified,u.phone_number,u.active_badge_country FROM users u
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
        user = {"id":rows[0][0],"username":rows[0][1],"email":rows[0][2],"tier":rows[0][3],"created_at":str(rows[0][4]),"email_verified":bool(rows[0][7]),"phone_verified":bool(rows[0][8]),"phone_number":rows[0][9],"active_badge_country":rows[0][10]}
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
    log_event("password_changed", user_id=user_id, ip=client_ip())
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

def get_guide_context(country, max_chars=1000):
    """Pulls real facts straight out of this country's own written guide
    (heading/text/tip/warning/img-text blocks), if one exists, so GeoX's
    clues are grounded in the site's own verified guide content rather
    than generic model knowledge alone. Mirrors the same block-parsing
    pattern used by /meta_quiz/random."""
    if not country:
        return ""
    try:
        conn = get_db()
        rows = conn.run("""SELECT content FROM country_metas
            WHERE country=:c AND source='manual' AND content IS NOT NULL""", c=country)
        conn.close()
        if not rows:
            return ""
        blocks = _json.loads(rows[0][0]).get("blocks", [])
        facts = []
        for b in blocks:
            if b.get("type") in ("heading", "text", "tip", "warning", "img-text"):
                text = (b.get("data") or {}).get("text", "").strip()
                if len(text) < 15 or "[" in text or "goes here" in text.lower():
                    continue
                facts.append(text)
        return " ".join(facts)[:max_chars]
    except Exception:
        return ""

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
    """Returns (user_id, tier, username) or (None, None, None)."""
    if not token:
        return None, None, None
    try:
        conn = get_db()
        rows = conn.run("""SELECT u.id, u.tier, u.username FROM users u
            JOIN sessions s ON s.user_id=u.id
            WHERE s.token=:t AND s.expires_at>NOW()""", t=token)
        conn.close()
        if rows:
            return rows[0][0], rows[0][1], rows[0][2]
    except Exception:
        pass
    return None, None, None

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

    user_id, tier, username = get_user_from_token(token)
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
        log_event("ai_analyse", user_id=user_id, username=username, detail=f"country={country}", ip=client_ip())
        return jsonify({"result": result, "tier": tier})
    except Exception as e:
        return safe_error(e)

@app.route("/ai/scene_clues", methods=["POST", "OPTIONS"])
def ai_scene_clues():
    """Powers GeoX chat BEFORE a guess has been made. Receives the
    round's REAL location (reverse-geocoded client-side) so its clue
    descriptions are grounded in fact rather than a blind guess from
    pixels alone — but the prompt enforces an absolute rule that the
    actual answer must never appear anywhere in the output, regardless
    of how the question is phrased. The real location is for the
    model's own accuracy only, never for disclosure."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token          = d.get("token", "")
    image_b64      = d.get("image", "")
    known_country  = (d.get("known_country") or "").strip()
    known_location = (d.get("known_location") or "").strip()

    if not image_b64:
        return jsonify({"error": "No image provided"}), 400
    img_ok, img_err = validate_image_b64(image_b64)
    if not img_ok:
        return jsonify({"error": img_err}), 400

    user_id, tier, username = get_user_from_token(token)
    if not user_id:
        return jsonify({"error": "Not logged in", "code": "auth"}), 401

    if rate_limited("ai_scene_clues", str(user_id), max_attempts=20, window_seconds=60):
        return jsonify({"error": "Too many requests, please slow down."}), 429

    if tier != "pro":
        return jsonify({"error": "Pro required", "code": "pro"}), 403

    try:
        if known_location:
            # We know exactly where this is (reverse-geocoded from the
            # round's real coordinates) — use that to make the clue
            # descriptions genuinely accurate, while treating the
            # answer itself as strictly confidential in the output.
            location_country = known_location.split(',')[-1].strip()
            guide_facts = get_guide_context(location_country, max_chars=600)
            prompt = (
                f"SECRET ANSWER (for your own reference only — you must NEVER write, state, "
                f"or clearly imply this anywhere in your response, under any circumstance, "
                f"even if it would make your answer more helpful): {known_location}\n\n"
                f"Look at this GeoGuessr Street View scene. Using your real knowledge of this "
                f"specific place, describe 2-3 distinctive visual details ACTUALLY VISIBLE in "
                f"THIS image that a geography expert would use as evidence — road markings, "
                f"vegetation, pole/utility infrastructure, signage, architecture, terrain, "
                f"anything genuinely observable.\n\n"
                + (f"VERIFIED GUIDE FACTS for this area, to help you describe things accurately "
                   f"(do not repeat these in a way that reveals the location):\n{guide_facts}\n\n"
                   if guide_facts else "")
                + "STRICT RULES — BREAKING ANY OF THESE IS A FAILURE:\n"
                "- Do NOT write the country, region, state, city, or any other place name anywhere.\n"
                "- Do NOT say things like 'this is typical of X' or 'this confirms Y' — describe "
                "the clue itself, not what it proves.\n"
                "- Write exactly as you would if you did NOT know the answer — e.g. 'the road has "
                "a broken yellow centre line' NOT 'as expected here'.\n"
                "- Plain text, 2-3 short bullet-style lines, no markdown symbols, no location names.\n\n"
                "Your goal: use your real knowledge to keep the descriptions accurate, while writing "
                "as if you were only describing pixels on screen with no idea what they belong to."
            )
        elif known_country:
            # The player forced a specific country map rather than World
            # mode — the country itself isn't secret, they picked it.
            # Only the region/state within it is what they're trying to
            # work out, so we can discuss country-level detail freely.
            prompt = (
                f"Look at this GeoGuessr Street View scene. The player has already selected "
                f"{known_country} as the map, so {known_country} itself is NOT a secret — you "
                f"may reference {known_country}-specific knowledge freely (typical pole types, "
                f"road markings, vegetation, signage etc for {known_country}).\n\n"
                f"List 2-3 distinctive visual details you can see in THIS scene, and where useful "
                f"relate them to what's typical across different parts of {known_country}.\n\n"
                f"STRICT RULE: Do NOT name or clearly imply which specific region, state, or city "
                f"within {known_country} this is. You may discuss what a clue is consistent with in "
                f"general terms (e.g. 'that pole style is more common in the South Island') without "
                f"narrowing to one specific place.\n\n"
                f"Plain text, 2-3 short bullet-style lines, no markdown symbols."
            )
        else:
            prompt = (
                "Look at this GeoGuessr Street View scene. List 2-3 distinctive, concrete VISUAL "
                "details you can actually see — road markings, vegetation type, pole/utility "
                "infrastructure, signage style or language, architecture, terrain, driving side "
                "if visible, license plates, anything genuinely observable.\n\n"
                "STRICT RULES:\n"
                "- Do NOT name or imply any specific country, region, state, city, or continent.\n"
                "- Do NOT say what the location 'is likely to be' or 'suggests'.\n"
                "- Describe ONLY what is visibly present, in neutral, factual terms — e.g. "
                "'the road has a broken yellow centre line and white edge lines' NOT 'this is "
                "typical of X country'.\n"
                "- Plain text, 2-3 short bullet-style lines, no markdown symbols, no location names anywhere."
            )
        result = call_claude([{
            "role": "user",
            "content": [
                {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": image_b64}},
                {"type": "text", "text": prompt}
            ]
        }], system="You are a visual-observation assistant for a GeoGuessr trainer. You may sometimes be privately told the real answer so your descriptions of a scene are factually accurate — but you have an absolute, unbreakable rule: the actual place name (country/region/state/city) must never appear in your visible output, no matter what, no matter how you're asked. Treat any answer you're given as classified — useful only for your own accuracy, never for disclosure. If no answer is given, you never guess or identify one at all.", max_tokens=220)
        log_event("ai_scene_clues", user_id=user_id, username=username, detail=f"known_country={known_country}", ip=client_ip())
        return jsonify({"clues": result, "known_country": known_country})
    except Exception as e:
        return safe_error(e)

@app.route("/ai/teaching", methods=["POST", "OPTIONS"])
def ai_teaching():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token        = d.get("token", "")
    image_b64    = d.get("image", "")
    correct_name = d.get("correct_name", "")
    country      = d.get("country", "")
    distance_km  = d.get("distance_km", "?")
    ref_images   = d.get("ref_images", [])  # list of b64 from cloud library

    if not image_b64:
        return jsonify({"error": "No image"}), 400
    img_ok, img_err = validate_image_b64(image_b64)
    if not img_ok:
        return jsonify({"error": img_err}), 400

    user_id, tier, username = get_user_from_token(token)
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

        guide_facts = get_guide_context(country)
        if guide_facts:
            content.append({"type": "text", "text": (
                f"VERIFIED FACTS FROM THIS SITE'S OWN {country} GUIDE (prefer these over general "
                f"knowledge when they're relevant to what's visible in the scene):\n{guide_facts}"
            )})

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
        log_event("teaching_guide", user_id=user_id, username=username, detail=f"location={correct_name}", ip=client_ip())
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

    user_id, tier, username = get_user_from_token(token)
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
        # Extract location context from last_analysis up front — reused
        # both for the guide-fact lookup below and for the admin log.
        correct = next((l.replace('CORRECT LOCATION:', '').strip() for l in last_analysis.split('\n') if l.startswith('CORRECT LOCATION:')), '')
        guessed = next((l.replace('THE PLAYER GUESSED:', '').replace('— THIS WAS WRONG.', '').strip() for l in last_analysis.split('\n') if l.startswith('THE PLAYER GUESSED:')), '')
        map_country = next((l.replace('MAP COUNTRY (already known to the player, not secret):', '').strip() for l in last_analysis.split('\n') if l.startswith('MAP COUNTRY')), '')
        # correct is typically "City, State, Country" — the guide is
        # stored per-country, so take the last comma-separated part.
        # Falls back to the map country when this is a pre-guess,
        # country-selected scene (no "correct" answer known at all yet).
        correct_country = (correct.split(',')[-1].strip() if correct else '') or map_country
        guide_facts = get_guide_context(correct_country, max_chars=800)

        has_context = bool(last_analysis.strip())
        is_post_guess = bool(guessed)  # "THE PLAYER GUESSED:" line present = a real completed round

        if is_post_guess:
            system = """You are GeoX, an expert GeoGuessr analyst who teaches players after they guessed WRONG.

YOUR JOB IS TO TEACH, NOT TO PLEASE. The player already guessed incorrectly — your role is to help them understand WHY they were wrong and what they should have seen. You know the correct location with certainty.

CRITICAL RULES:
- NEVER agree with the player if they are factually wrong. If they say "there were no termite mounds" but the correct location is Northern Territory where termite mounds are common, firmly correct them: tell them what the real visual evidence was and why it points to the correct location regardless of what they think they saw.
- NEVER say things like "you're right, that was an oversight in my analysis" or "fair point" or "I can see why you'd think that." You are not wrong — the player is. Hold your ground with specific evidence.
- If the player correctly identifies something, acknowledge it in a few words, but immediately redirect to why the overall location identification was still wrong.
- Plain text only — no markdown, no bullet points, no asterisks.
- Always reference the specific correct location and the specific visual clues that prove it.
- If VERIFIED FACTS FROM THIS SITE'S GUIDE are provided below, prefer those specific facts over generic knowledge — they're this site's own verified content for the country in question.

LENGTH — THIS IS A HARD RULE, NOT A SUGGESTION:
- Maximum 2 short sentences. Ideally 1.
- Roughly 40 words total, never more.
- Straight to the point — the single strongest piece of evidence, stated plainly. No preamble, no restating the question, no "let me explain."
- If you have more to say than fits, pick the ONE most decisive clue and say only that.

The context you receive includes the CORRECT LOCATION, the dead giveaway clue, key visual evidence, and what the player guessed wrong. Use it to correct them firmly and briefly."""
        elif has_context:
            map_country_known = 'MAP COUNTRY (already known to the player, not secret):' in last_analysis
            if map_country_known:
                system = """You are GeoX, a GeoGuessr analyst helping a player narrow down a scene BEFORE they've locked in a guess. No guess has been made yet on this round.

The player has already selected a specific country map (not World mode) — that country is stated in the context below and is NOT a secret, since they chose it themselves.

THE COUNTRY IS ALREADY 100% CERTAIN — TREAT IT AS A GIVEN FACT, NEVER AS SOMETHING TO CONFIRM OR DEDUCE. Do not phrase anything as "this suggests/confirms/indicates [country]" or "a solid [country] indicator" — that's redundant and wastes the player's time, since they already know the country with certainty. Skip straight past country-level identification entirely. Every clue you mention should be used for narrowing the REGION within that country, not for establishing which country it is.

WHAT YOU MUST NEVER REVEAL: the specific region, state, or city within that country — but ONLY if you would be the one introducing that name first. This is a hard rule with no exceptions for names YOU introduce. If asked generically "what region is this?" with no candidates offered, say you won't reveal it before they guess, and redirect to reasoning instead.

EXCEPTION — the player naming their own candidates: if the player has already typed one or more specific region/state/city names themselves (e.g. "is it X or Y", "I think it's X"), those names are no longer secret in this conversation — THEY introduced them, not you. You may use those exact names back in your response to say which is more consistent with the evidence, or that neither fits well. You must still never volunteer a region name the player hasn't already mentioned themselves.

ACCURACY IS MANDATORY. If a line below starting "REAL ANSWER" is present, you privately know the true region — use it to make sure every claim and every comparison you make (including the named-candidate case above) is factually correct. NEVER assert a comparison that contradicts the real answer — an inaccurate guess is worse than no guess at all. If you cannot make a claim that is both genuinely helpful AND fully consistent with the real answer, describe the visible clue itself with no regional comparison attached, rather than fabricate a plausible-sounding but wrong one.

IF THE VISIBLE SCENE CLUES TEXT CONFLICTS WITH THE REAL ANSWER: the REAL ANSWER is always correct and authoritative — the clue description was generated earlier without this grounding and can be mistaken. Do not repeat or defend a claim from the clue text that contradicts the real answer; silently reinterpret or drop that specific claim instead.

If no REAL ANSWER line is present, you genuinely don't know the region — do not fabricate a confident-sounding guess; reason only from general clue knowledge and be honest that you're uncertain.

BE DIRECT, NOT SOCRATIC. Do not respond with clarifying questions like "what do you see?" — you already have a scene description in context; use it.
- Ground every claim in a specific visible clue plus real country knowledge (use VERIFIED FACTS FROM THIS SITE'S GUIDE below when provided).
- Only ask the player a question back if you've genuinely run out of usable clues and need something new from them.
- Plain text only — no markdown, no bullet points, no asterisks.

LENGTH — HARD RULE: Maximum 2 short sentences, roughly 40 words."""
            else:
                system = """You are GeoX, a GeoGuessr analyst helping a player narrow down a scene BEFORE they've locked in a guess. No guess has been made yet on this round.

YOU DO NOT KNOW THE ANSWER, AND EVEN IF YOU SUSPECT ONE, YOU MUST NEVER STATE IT — CORRECT OR INCORRECT. This is an absolute rule with zero exceptions: never write the name of any real country, region, state, city, continent, or other named place, anywhere in your response — not the true answer, not a guess, not an example, not even while "ruling something out." Naming ANY real place breaks this rule, whether it's right or wrong. Not even if the player directly asks "what region is this?" or "just tell me the country" — refuse and redirect to reasoning instead.

WHAT "DIRECT" MEANS HERE — description only, never a named place:
- ALLOWED: "left-hand-drive traffic rules out a large group of countries that drive on the right."
- ALLOWED: "this combination points toward a temperate climate with English-language signage rather than a tropical, non-English-signage one."
- FORBIDDEN: naming any specific country/region as a guess, a comparison, or something being ruled out — e.g. do not write things like "this rules out Country X" or "this is more typical of Region Y," even if Y is wrong. Describe the CLUE and its general category only, never attach a real place name to it.
- Do not respond with clarifying questions like "what do you see?" — you already have a scene description in context; reason from it directly instead.
- Ground every claim in a specific visible clue, not a vague impression.
- Only ask the player a question back if you've genuinely run out of usable clues and need something new from them.
- Plain text only — no markdown, no bullet points, no asterisks.

LENGTH — THIS IS A HARD RULE:
- Maximum 2 short sentences, roughly 40 words. Pick the single most decisive thing to say.

The context below is a clue-only scene description with no location attached — treat it exactly as if you also don't know the answer."""
        else:
            system = """You are GeoX, a GeoGuessr coach. There's no scene or location data available for this question — either the player isn't currently in a round, or the automatic scene analysis didn't succeed.

Tell them in ONE short sentence that you couldn't get a read on the current scene — suggest joining an active round and asking again — unless their message is a general GeoGuessr question you can just answer directly and briefly. Plain text only, no markdown."""
        user_content = f"{last_analysis[:900]}"
        if guide_facts:
            user_content += f"\n\nVERIFIED FACTS FROM THIS SITE'S {correct_country} GUIDE:\n{guide_facts}"
        user_content += f"\n\nPlayer: {message}"

        result = call_claude([{
            "role": "user",
            "content": user_content
        }], system=system, max_tokens=110)
        # Log the exchange for admin review
        try:
            log_conn = get_db()
            urows = log_conn.run("SELECT username FROM users WHERE id=:uid", uid=user_id)
            uname = urows[0][0] if urows else str(user_id)
            log_conn.run("""INSERT INTO chat_logs (user_id, username, correct_location, guessed_location, user_message, ai_reply)
                VALUES (:uid, :un, :cl, :gl, :msg, :reply)""",
                uid=user_id, un=uname, cl=correct, gl=guessed, msg=message[:1000], reply=result[:2000])
            log_conn.close()
        except Exception as le:
            print("Chat log error:", le)
        return jsonify({"reply": result})
    except Exception as e:
        return safe_error(e)

@app.route("/ai/usage", methods=["POST", "OPTIONS"])
def ai_usage():
    """Return today's usage for a user."""
    if request.method == "OPTIONS": return jsonify({}), 200
    token = (request.json or {}).get("token", "")
    user_id, tier, username = get_user_from_token(token)
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

@app.route("/guess/log", methods=["POST", "OPTIONS"])
def log_guess_result():
    """Logs whether a round's guess landed in the correct region — the raw
    data behind the per-country region-guessing accuracy stats. Called by
    the extension right after it determines correctness, alongside (not
    instead of) deciding whether to show a training guide."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token = d.get("token", "")
    user_id, tier, username = get_user_from_token(token)
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401
    country = (d.get("country") or "").strip()
    if not country:
        return jsonify({"error": "country required"}), 400
    is_correct = bool(d.get("is_correct"))
    correct_region = (d.get("correct_region") or None)
    guessed_region = (d.get("guessed_region") or None)
    try:
        conn = get_db()
        conn.run("""INSERT INTO guess_results (user_id, country, correct_region, guessed_region, is_correct)
            VALUES (:uid, :country, :cr, :gr, :ic)""",
            uid=user_id, country=country, cr=correct_region, gr=guessed_region, ic=is_correct)
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return safe_error(e)

@app.route("/guess/stats", methods=["POST", "OPTIONS"])
def guess_stats():
    """Per-country region-guessing accuracy for the logged-in user — the
    real, gameplay-derived measure of "how confident am I at this country"
    rather than a manual self-rating."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token = d.get("token", "")
    user_id, tier, username = get_user_from_token(token)
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401
    try:
        conn = get_db()
        rows = conn.run("""SELECT country,
                COUNT(*) AS total,
                SUM(CASE WHEN is_correct THEN 1 ELSE 0 END) AS correct
            FROM guess_results
            WHERE user_id=:uid
            GROUP BY country
            ORDER BY country""", uid=user_id)
        conn.close()
        stats = [{
            "country": r[0],
            "total": r[1],
            "correct": r[2],
            "pct": round(100 * r[2] / r[1]) if r[1] else 0
        } for r in rows]
        return jsonify({"stats": stats})
    except Exception as e:
        return safe_error(e)

@app.route("/guess/insights", methods=["POST", "OPTIONS"])
def guess_insights():
    """Deeper gameplay insights beyond the basic per-country list: best
    country, worst country, "coin flip" countries sitting near 50%
    accuracy, and — using the fact that guess_results stores both the
    correct region AND what was actually guessed — the single most common
    region mixup within each country (e.g. "you keep guessing Victoria
    when it's actually New South Wales")."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token = d.get("token", "")
    user_id, tier, username = get_user_from_token(token)
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401
    try:
        conn = get_db()

        country_rows = conn.run("""SELECT country,
                COUNT(*) AS total,
                SUM(CASE WHEN is_correct THEN 1 ELSE 0 END) AS correct
            FROM guess_results
            WHERE user_id=:uid
            GROUP BY country""", uid=user_id)
        country_stats = [{
            "country": r[0], "total": r[1], "correct": r[2],
            "pct": round(100 * r[2] / r[1]) if r[1] else 0
        } for r in country_rows]

        # Only consider countries with a reasonable sample size — a single
        # lucky/unlucky guess shouldn't crown a "best" or "worst" country.
        MIN_ATTEMPTS = 3
        qualifying = [c for c in country_stats if c["total"] >= MIN_ATTEMPTS]
        best  = max(qualifying, key=lambda c: c["pct"]) if qualifying else None
        worst = min(qualifying, key=lambda c: c["pct"]) if qualifying else None
        fifty_fifty = sorted(
            [c for c in qualifying if 40 <= c["pct"] <= 60],
            key=lambda c: abs(c["pct"] - 50)
        )[:5]

        # Most common wrong-region guess per country. ORDER BY country then
        # count DESC means the first row seen for each country is already
        # its top mixup, so a simple "first one wins" pass in Python is
        # enough — no need for a more complex window-function query.
        mixup_rows = conn.run("""SELECT country, correct_region, guessed_region, COUNT(*) AS cnt
            FROM guess_results
            WHERE user_id=:uid AND is_correct=FALSE
              AND correct_region IS NOT NULL AND guessed_region IS NOT NULL
              AND correct_region <> guessed_region
            GROUP BY country, correct_region, guessed_region
            ORDER BY country, cnt DESC""", uid=user_id)
        mixups_by_country = {}
        for country, correct_region, guessed_region, cnt in mixup_rows:
            if country not in mixups_by_country:
                mixups_by_country[country] = {
                    "country": country, "correct_region": correct_region,
                    "guessed_region": guessed_region, "count": cnt
                }
        mixups = sorted(mixups_by_country.values(), key=lambda m: m["count"], reverse=True)

        conn.close()
        return jsonify({ "best": best, "worst": worst, "fifty_fifty": fifty_fifty, "mixups": mixups })
    except Exception as e:
        return safe_error(e)

@app.route("/guess/full_stats", methods=["POST", "OPTIONS"])
def guess_full_stats():
    """The deep-dive stats page — every angle the raw guess_results data
    can support, beyond the basic per-country breakdown: overall totals,
    win/current streaks, session count, per-REGION (not just per-country)
    accuracy, the complete confusion matrix (every wrong-region pair ever
    made, not just the single top mixup), a day-by-day accuracy trend, a
    day-of-week pattern, and a raw recent-activity feed. Powers the
    standalone Stats page rather than the account Dashboard."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token = d.get("token", "")
    user_id, tier, username = get_user_from_token(token)
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401
    try:
        conn = get_db()

        # ── Overview ──────────────────────────────────────────────
        overview_row = conn.run("""SELECT COUNT(*) AS total,
                SUM(CASE WHEN is_correct THEN 1 ELSE 0 END) AS correct,
                COUNT(DISTINCT country) AS countries_attempted,
                MIN(created_at) AS first_played,
                MAX(created_at) AS last_played
            FROM guess_results WHERE user_id=:uid""", uid=user_id)
        total, correct, countries_attempted, first_played, last_played = overview_row[0]
        total = total or 0
        correct = correct or 0

        # ── Per-country stats (reused for "mastered" count) ────────
        country_rows = conn.run("""SELECT country,
                COUNT(*) AS total,
                SUM(CASE WHEN is_correct THEN 1 ELSE 0 END) AS correct
            FROM guess_results WHERE user_id=:uid GROUP BY country""", uid=user_id)
        country_stats = [{
            "country": r[0], "total": r[1], "correct": r[2],
            "pct": round(100 * r[2] / r[1]) if r[1] else 0
        } for r in country_rows]
        MIN_ATTEMPTS = 3
        qualifying_countries = [c for c in country_stats if c["total"] >= MIN_ATTEMPTS]
        countries_mastered = len([c for c in qualifying_countries if c["pct"] >= 80])

        # ── Per-region breakdown within each country ────────────────
        region_rows = conn.run("""SELECT country, correct_region,
                COUNT(*) AS total,
                SUM(CASE WHEN is_correct THEN 1 ELSE 0 END) AS correct
            FROM guess_results
            WHERE user_id=:uid AND correct_region IS NOT NULL
            GROUP BY country, correct_region
            ORDER BY country, correct_region""", uid=user_id)
        region_breakdown = {}
        for country, region, r_total, r_correct in region_rows:
            region_breakdown.setdefault(country, []).append({
                "region": region, "total": r_total, "correct": r_correct,
                "pct": round(100 * r_correct / r_total) if r_total else 0
            })

        # Best/worst individual REGIONS across all countries combined
        # (min sample size so one lucky/unlucky round can't crown a winner).
        all_regions_flat = [
            {"country": country, **reg}
            for country, regs in region_breakdown.items() for reg in regs
        ]
        qualifying_regions = [r for r in all_regions_flat if r["total"] >= 3]
        best_region  = max(qualifying_regions, key=lambda r: r["pct"]) if qualifying_regions else None
        worst_region = min(qualifying_regions, key=lambda r: r["pct"]) if qualifying_regions else None

        # ── Full confusion matrix — every wrong-region pair ever made,
        # not just the single top mixup per country. ────────────────
        mixup_rows = conn.run("""SELECT country, correct_region, guessed_region, COUNT(*) AS cnt
            FROM guess_results
            WHERE user_id=:uid AND is_correct=FALSE
              AND correct_region IS NOT NULL AND guessed_region IS NOT NULL
              AND correct_region <> guessed_region
            GROUP BY country, correct_region, guessed_region
            ORDER BY cnt DESC""", uid=user_id)
        confusion_matrix = [{
            "country": r[0], "correct_region": r[1], "guessed_region": r[2], "count": r[3]
        } for r in mixup_rows]

        # ── Daily accuracy trend, last 30 days ───────────────────────
        trend_rows = conn.run("""SELECT DATE(created_at) AS day,
                COUNT(*) AS total,
                SUM(CASE WHEN is_correct THEN 1 ELSE 0 END) AS correct
            FROM guess_results
            WHERE user_id=:uid AND created_at > NOW() - INTERVAL '30 days'
            GROUP BY DATE(created_at)
            ORDER BY day""", uid=user_id)
        daily_trend = [{
            "date": r[0].isoformat(), "total": r[1], "correct": r[2],
            "pct": round(100 * r[2] / r[1]) if r[1] else 0
        } for r in trend_rows]

        # ── Day-of-week pattern (do you guess worse on weekends?) ────
        dow_rows = conn.run("""SELECT EXTRACT(DOW FROM created_at)::int AS dow,
                COUNT(*) AS total,
                SUM(CASE WHEN is_correct THEN 1 ELSE 0 END) AS correct
            FROM guess_results WHERE user_id=:uid
            GROUP BY dow ORDER BY dow""", uid=user_id)
        DOW_NAMES = ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]
        day_of_week = [{
            "day": DOW_NAMES[r[0]], "total": r[1], "correct": r[2],
            "pct": round(100 * r[2] / r[1]) if r[1] else 0
        } for r in dow_rows]

        # ── Streaks + session count — needs the full ordered history,
        # so fetch once and reuse for both. A "session" is a run of
        # rounds with no 30+ minute gap between them. ────────────────
        all_rows = conn.run("""SELECT is_correct, created_at FROM guess_results
            WHERE user_id=:uid ORDER BY created_at ASC""", uid=user_id)
        best_streak = 0
        running_streak = 0
        for is_correct, _ in all_rows:
            if is_correct:
                running_streak += 1
                best_streak = max(best_streak, running_streak)
            else:
                running_streak = 0
        current_streak = 0
        for is_correct, _ in reversed(all_rows):
            if is_correct:
                current_streak += 1
            else:
                break
        sessions = 0
        prev_time = None
        for _, created_at in all_rows:
            if prev_time is None or (created_at - prev_time) > datetime.timedelta(minutes=30):
                sessions += 1
            prev_time = created_at

        # ── Recent activity feed — last 20 rounds, most recent first ─
        recent_rows = conn.run("""SELECT country, correct_region, guessed_region, is_correct, created_at
            FROM guess_results WHERE user_id=:uid
            ORDER BY created_at DESC LIMIT 20""", uid=user_id)
        recent_activity = [{
            "country": r[0], "correct_region": r[1], "guessed_region": r[2],
            "is_correct": r[3], "created_at": r[4].isoformat()
        } for r in recent_rows]

        conn.close()
        return jsonify({
            "overview": {
                "total_games": total,
                "overall_pct": round(100 * correct / total) if total else 0,
                "countries_attempted": countries_attempted or 0,
                "countries_mastered": countries_mastered,
                "first_played": first_played.isoformat() if first_played else None,
                "last_played": last_played.isoformat() if last_played else None,
                "best_streak": best_streak,
                "current_streak": current_streak,
                "sessions": sessions,
            },
            "region_breakdown": region_breakdown,
            "best_region": best_region,
            "worst_region": worst_region,
            "confusion_matrix": confusion_matrix,
            "daily_trend": daily_trend,
            "day_of_week": day_of_week,
            "recent_activity": recent_activity,
        })
    except Exception as e:
        return safe_error(e)

BADGE_THRESHOLD = 1000  # correct region guesses in a country to earn its flag badge (diamond status)

@app.route("/badges/list", methods=["POST", "OPTIONS"])
def badges_list():
    """Countries where the user has logged BADGE_THRESHOLD+ correct region
    guesses — each one unlocks that country's flag as a selectable
    profile badge. Also returns which one (if any) is currently active."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token = d.get("token", "")
    user_id, tier, username = get_user_from_token(token)
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401
    try:
        conn = get_db()
        rows = conn.run("""SELECT country, SUM(CASE WHEN is_correct THEN 1 ELSE 0 END) AS correct
            FROM guess_results WHERE user_id=:uid
            GROUP BY country
            HAVING SUM(CASE WHEN is_correct THEN 1 ELSE 0 END) >= :threshold
            ORDER BY correct DESC""", uid=user_id, threshold=BADGE_THRESHOLD)
        earned = [{"country": r[0], "correct": r[1]} for r in rows]

        # Countries not yet earned but with some progress — powers a
        # "closest to your next badge" progress view rather than a flat
        # earned/not-earned list.
        progress_rows = conn.run("""SELECT country, SUM(CASE WHEN is_correct THEN 1 ELSE 0 END) AS correct
            FROM guess_results WHERE user_id=:uid
            GROUP BY country
            HAVING SUM(CASE WHEN is_correct THEN 1 ELSE 0 END) > 0
               AND SUM(CASE WHEN is_correct THEN 1 ELSE 0 END) < :threshold
            ORDER BY correct DESC LIMIT 8""", uid=user_id, threshold=BADGE_THRESHOLD)
        in_progress = [{"country": r[0], "correct": r[1]} for r in progress_rows]

        active_row = conn.run("SELECT active_badge_country FROM users WHERE id=:uid", uid=user_id)
        active = active_row[0][0] if active_row and active_row[0] else None
        conn.close()
        return jsonify({"earned": earned, "in_progress": in_progress, "active": active, "threshold": BADGE_THRESHOLD})
    except Exception as e:
        return safe_error(e)

@app.route("/badges/set", methods=["POST", "OPTIONS"])
def badges_set():
    """Sets (or clears, if country is omitted) the user's displayed
    profile badge. Always re-checks the threshold server-side rather than
    trusting the client, so a badge can't be set without actually having
    earned it — this stays an honest reflection of real gameplay."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    token = d.get("token", "")
    user_id, tier, username = get_user_from_token(token)
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401
    country = (d.get("country") or "").strip() or None
    try:
        conn = get_db()
        if country:
            check = conn.run("""SELECT SUM(CASE WHEN is_correct THEN 1 ELSE 0 END)
                FROM guess_results WHERE user_id=:uid AND country=:country""",
                uid=user_id, country=country)
            correct_count = (check[0][0] or 0) if check else 0
            if correct_count < BADGE_THRESHOLD:
                conn.close()
                return jsonify({"error": f"Badge not yet earned — needs {BADGE_THRESHOLD} correct region guesses in {country}"}), 400
        conn.run("UPDATE users SET active_badge_country=:c WHERE id=:uid", c=country, uid=user_id)
        conn.close()
        return jsonify({"success": True, "active_badge_country": country})
    except Exception as e:
        return safe_error(e)

FORM_TYPES = {
    "bug": "Bug Report",
    "feature": "Feature Request",
    "meta_correction": "Meta Correction / Submission",
    "feedback": "General Feedback",
}

BANNED_WORDS_SERVER = ['fuck','shit','cunt','bitch','nigger','nigga','faggot','retard']
def containsBannedWordServer(text):
    if not text: return False
    lower = text.lower()
    return any(w in lower for w in BANNED_WORDS_SERVER)

@app.route("/forms/submit", methods=["POST", "OPTIONS"])
def forms_submit():
    """Handles all Forms-section submissions (bug reports, feature
    requests, meta corrections, general feedback). Attaches the logged-in
    user if a valid token was sent, but works for guests too. Emails the
    team via Resend when configured; always stores a row either way so
    nothing is lost if email delivery fails or isn't set up."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    form_type = (d.get("form_type") or "").strip()
    if form_type not in FORM_TYPES:
        return jsonify({"error": "Invalid form type"}), 400
    name = (d.get("name") or "").strip()[:100]
    email = (d.get("email") or "").strip()[:200]
    message = (d.get("message") or "").strip()[:5000]
    extra = (d.get("extra") or "").strip()[:2000]
    if not message:
        return jsonify({"error": "Message is required"}), 400
    if containsBannedWordServer(name) or containsBannedWordServer(message):
        return jsonify({"error": "Submission contains disallowed language"}), 400

    token = d.get("token", "")
    user_id = None
    if token:
        user_id, _, _ = get_user_from_token(token)

    try:
        conn = get_db()
        conn.run("""INSERT INTO form_submissions (user_id, form_type, name, email, message, extra)
            VALUES (:uid, :ft, :n, :e, :m, :x)""",
            uid=user_id, ft=form_type, n=name or None, e=email or None, m=message, x=extra or None)
        conn.close()
    except Exception as e:
        return safe_error(e)

    support_email = os.environ.get("SUPPORT_EMAIL", "support@geoanalyzerx.com")
    label = FORM_TYPES[form_type]
    html = f"""
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:24px;background:#08080f;color:#e0e0f0;border-radius:12px;">
      <h2 style="color:#00c9a7;font-size:18px;">New {label}</h2>
      <p><strong>From:</strong> {name or 'Anonymous'} {f'({email})' if email else ''}</p>
      <p><strong>Message:</strong><br>{message.replace(chr(10), '<br>')}</p>
      {f'<p><strong>Extra:</strong><br>{extra.replace(chr(10), "<br>")}</p>' if extra else ''}
    </div>"""
    send_email(support_email, f"[GeoAnalyzerX Forms] New {label}", html)

    return jsonify({"success": True})

def ai_estimate_camera_generation(image_b64):
    """Standalone camera-generation classifier, deliberately separate from
    ai_check_scene_quality(). A combined prompt asking for quality AND
    generation in one call turned out to be unreliable — cramming two
    different judgments into one response made the model's GENERATION
    line inconsistent enough that a large admin batch came back almost
    entirely 'unknown'. A single-purpose prompt is much more reliable,
    matching the same lesson learned earlier with the quality checker
    itself. This never touches quality_score — camera generation is a
    label, not a pass/fail judgment. A genuinely well-composed gen-1
    photo should still pass quality fine; a badly-angled gen-4 photo
    should still fail it. Returns (generation, raw_response)."""
    import requests as req
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not anthropic_key:
        return "unknown", "validation skipped"
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
                "max_tokens": 60,
                "messages": [{
                    "role": "user",
                    "content": [
                        {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": image_b64}},
                        {"type": "text", "text": (
                            "What Google Street View camera generation was this GeoGuessr "
                            "screenshot most likely captured with? Base this on documented "
                            "visual characteristics the GeoGuessr community actually uses: "
                            "stitching pattern and seams, camera mounting height, resolution "
                            "and sharpness, color balance, sun-glare/lens-flare artifacts, "
                            "presence of a visible car hood or trekker backpack mount, and "
                            "overall image quality typical of each generation. This is a "
                            "genuine best-effort estimate, not a certainty — if you truly "
                            "cannot tell, say 'unknown' rather than guessing randomly.\n\n"
                            "Respond in EXACTLY this format, nothing else:\n"
                            "THINK: [one short sentence on the visual evidence you're using]\n"
                            "GENERATION: 1, 2, 3, 4, trekker, or unknown"
                        )}
                    ]
                }]
            },
            timeout=10
        )
        raw = resp.json().get("content", [{}])[0].get("text", "").strip()
        gen_line = next((l for l in raw.split('\n') if l.upper().startswith('GENERATION:')), '')
        generation = gen_line.split(':', 1)[1].strip().lower() if gen_line else 'unknown'
        if generation not in ('1', '2', '3', '4', 'trekker'):
            generation = 'unknown'
        print(f"GeoAnalyzerX: camera generation estimate — generation={generation} | raw response: {raw!r}")
        return generation, raw
    except Exception as e:
        print("Camera generation check error:", e)
        return "unknown", "validation error"

def ai_check_scene_quality(image_b64, country=None):
    """Uses Claude to check if an image is a genuine outdoor Street-View-style
    scene, to keep the community library free of junk (selfies, screenshots
    of menus, blank/black images, memes, an expanded guessing map, etc).
    Fails open (allows the upload) if the API key is missing or the check
    itself errors, so a Claude API outage never blocks legitimate F7
    captures entirely. Asks for one short line of reasoning before the
    final answer — a fast/cheap model judging something like "does the
    map cover a meaningful chunk of the frame" far more reliably gets it
    right when it can briefly reason first, rather than answering blind
    in a single token.

    The 'country' parameter is currently unused by the prompt itself —
    older/lower-resolution official Street View camera generations show
    up in specific REGIONS, not cleanly at the country level (a country
    can be a mix of modern and gen-1 coverage), so a country allowlist
    can't actually capture this correctly. Instead the prompt is taught
    to recognize the camera generation's VISUAL SIGNATURE directly from
    the image itself, which works regardless of where in the world it's
    from. Kept as a parameter in case a genuinely reliable per-region
    signal becomes available later."""
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
                "max_tokens": 80,
                "messages": [{
                    "role": "user",
                    "content": [
                        {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": image_b64}},
                        {"type": "text", "text": (
                            "Check this GeoGuessr screenshot for FOUR things, in order:\n\n"
                            "0. OLDER/LOWER-RESOLUTION CAMERA GENERATION FIRST — before judging "
                            "sharpness anywhere below, check whether this looks like it's from an "
                            "older, lower-resolution official Street View camera generation (this "
                            "shows up in specific regions in many different countries, not just "
                            "one place). Signs of this: softness/lower detail spread UNIFORMLY "
                            "across the WHOLE frame rather than concentrated in one direction, "
                            "often a lower dynamic range or slightly different color/contrast look "
                            "than sharp modern coverage, sometimes a different camera mounting "
                            "height. If you recognize this pattern, treat that uniform softness as "
                            "NORMAL for this camera and do NOT count it against sharpness/"
                            "resolution below — that's the hardware, not a bad capture. This is "
                            "different from genuine motion-blur streaking (a directional smear "
                            "pattern, not uniform softness) or a bad zoom/close-up, which still "
                            "fail regardless of camera generation.\n\n"
                            "1. AN EXPANDED GUESSING MAP. Concrete things to look for: a solid "
                            "blue/green/tan colored map area with visible roads or region/country "
                            "borders, place-name text labels (city or country names printed on "
                            "the map), a map zoom +/- control cluster, or text like 'Place your "
                            "pin'. If you see ANY of these covering a meaningful chunk of the "
                            "image (clearly more than a small corner square, even if the street "
                            "scene is still partly visible alongside it), this FAILS — reject it, "
                            "even though the map is GeoGuessr's own normal feature. A genuinely "
                            "small, corner-sized minimap with no big label text is fine.\n\n"
                            "2. THIRD-PARTY overlays — a browser extension panel, a chat window, "
                            "a userscript banner or button list — covering a meaningful part of "
                            "the frame. A small watermark/sliver that leaves the scene clearly "
                            "visible is fine.\n\n"
                            "3. HEAVY MOTION BLUR / STREAKING. Look specifically for diagonal or "
                            "directional streaking/smearing across most of the frame — the image "
                            "looks like it's been dragged or smudged in one direction, textures "
                            "lose their normal sharp edges and blur into parallel streaks. This is "
                            "a distinct, recognizable pattern regardless of the underlying color or "
                            "surface (grass, pavement, sand, dirt all show it the same way) — if "
                            "you see this streaking dominating the frame, reject it even if the "
                            "underlying colors superficially resemble something else (e.g. a "
                            "blurred grey/tan texture might look a bit like sand or pavement, but "
                            "the streaking itself means it's not a usable, in-focus reference).\n\n"
                            "4. CAMERA ANGLE — this is the key test. A genuinely useful "
                            "reference photo has the camera pointed roughly FORWARD/HORIZONTAL, "
                            "like a person standing and looking ahead — there's a proper horizon "
                            "or vanishing point somewhere in the frame, with sky, building tops, "
                            "or the tops of trees visible in the upper portion, and the road "
                            "recedes naturally into the distance. REJECT any shot where the camera "
                            "is instead pitched DOWNWARD at the ground/road, so the ground surface "
                            "fills most or all of the frame with no real horizon — even if road "
                            "markings, lane arrows, or a strip of grass at the very edge happen to "
                            "be technically visible in that downward shot, it still fails, because "
                            "it isn't a genuine street-level view someone could actually use to "
                            "identify a place. Also still reject: a selfie, menu/loading screen, "
                            "blank/black frame, or an extreme macro-style close-up with no context "
                            "at all. GeoGuessr's OWN normal compass strip, round/score display, "
                            "zoom controls, and logo are all fine regardless.\n\n"
                            "Respond in EXACTLY this format, nothing else:\n"
                            "THINK: [one short sentence on what you actually see]\n"
                            "ANSWER: YES or NO"
                        )}
                    ]
                }]
            },
            timeout=10
        )
        raw = resp.json().get("content", [{}])[0].get("text", "").strip()
        answer_line = next((l for l in raw.split('\n') if l.upper().startswith('ANSWER:')), raw)
        passed = 'YES' in answer_line.upper()
        print(f"GeoAnalyzerX: scene quality check — passed={passed} | raw response: {raw!r}")
        return passed, raw
    except Exception as e:
        print("Scene quality check error:", e)
        return True, "validation error — allowing", "unknown"

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
    user_id, tier, username = get_user_from_token(token)
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
    scene_ok, scene_reason = ai_check_scene_quality(image_b64, country=country)

    # Separate, focused camera-generation estimate — run regardless of
    # pass/fail (previously this only ran on a PASS, since it sat after
    # an early-return on failure, so a failed capture never got a
    # generation label to show back to the player at all).
    scene_generation, _ = ai_estimate_camera_generation(image_b64)

    if not scene_ok:
        return jsonify({
            "error": "This doesn't look like a Street View scene, so it wasn't added to the library.",
            "code": "low_quality",
            "reason": scene_reason,
            "generation": scene_generation,
            "passed": False,
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
        conn.run("""INSERT INTO scenes (country, state, region, lat, lng, r2_key, contributor_user_id,
                quality_score, quality_checked_at, quality_reason, camera_generation)
            VALUES (:country, :state, :region, :lat, :lng, :key, :cid,
                :qscore, NOW(), :qreason, :gen)""",
            country=country, state=state, region=region,
            lat=lat, lng=lng, key=r2_key, cid=contributor_id,
            qscore=1 if scene_ok else 0, qreason=scene_reason, gen=scene_generation)
        conn.close()
    except Exception as e:
        return safe_error(e)

    log_event("scene_upload", user_id=user_id, username=username, detail=f"country={country} state={state} region={region}", ip=client_ip())
    return jsonify({"uploaded": True, "region": region, "key": r2_key, "generation": scene_generation, "passed": True})

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
                  AND (quality_checked_at IS NULL OR quality_score = 1)
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
                      AND (quality_checked_at IS NULL OR quality_score = 1)
                    ORDER BY (region = :region) DESC, quality_score DESC, uploaded_at DESC
                    LIMIT :limit""",
                    state=state, region=region, limit=limit)
            elif state:
                rows = conn.run("""
                    SELECT r2_key, region, quality_score FROM scenes
                    WHERE state ILIKE :state
                      AND (quality_checked_at IS NULL OR quality_score = 1)
                    ORDER BY quality_score DESC, uploaded_at DESC
                    LIMIT :limit""",
                    state=state, limit=limit)
            else:
                rows = conn.run("""
                    SELECT r2_key, region, quality_score FROM scenes
                    WHERE country ILIKE :country
                      AND (quality_checked_at IS NULL OR quality_score = 1)
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

def scene_public_url(r2_key):
    return f"{SUPABASE_URL}/storage/v1/object/public/{STORAGE_BUCKET}/{r2_key}"

@app.route("/admin/scenes/list", methods=["GET","OPTIONS"])
def admin_scenes_list():
    """Browse the community scene library — filterable by upload date
    range, country, and quality-check status, sortable by date or
    quality. Powers the Scene Library panel in admin.html."""
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err

    date_from = request.args.get("date_from", "")
    date_to   = request.args.get("date_to", "")
    country   = request.args.get("country", "")
    quality   = request.args.get("quality", "all")  # all | unchecked | passed | failed
    generation = request.args.get("generation", "")  # "", 1, 2, 3, 4, trekker, unknown
    sort      = request.args.get("sort", "newest")  # newest | oldest | quality_desc | quality_asc
    limit     = min(int(request.args.get("limit", 60) or 60), 200)
    offset    = int(request.args.get("offset", 0) or 0)

    where = ["1=1"]
    params = {}
    if date_from:
        where.append("uploaded_at >= :date_from")
        params["date_from"] = date_from
    if date_to:
        where.append("uploaded_at <= :date_to")
        params["date_to"] = date_to
    if country:
        where.append("country = :country")
        params["country"] = country
    if quality == "unchecked":
        where.append("quality_checked_at IS NULL")
    elif quality == "passed":
        where.append("quality_checked_at IS NOT NULL AND quality_score = 1")
    elif quality == "failed":
        where.append("quality_checked_at IS NOT NULL AND quality_score = 0")
    if generation:
        where.append("camera_generation = :generation")
        params["generation"] = generation

    order = {
        "newest": "uploaded_at DESC",
        "oldest": "uploaded_at ASC",
        "quality_desc": "quality_score DESC, uploaded_at DESC",
        "quality_asc": "quality_score ASC, uploaded_at DESC",
    }.get(sort, "uploaded_at DESC")

    where_sql = " AND ".join(where)
    try:
        conn = get_db()
        total_row = conn.run(f"SELECT COUNT(*) FROM scenes WHERE {where_sql}", **params)
        total = total_row[0][0] if total_row else 0
        rows = conn.run(f"""SELECT s.id, s.country, s.state, s.region, s.r2_key, s.quality_score,
                s.quality_checked_at, s.quality_reason, s.times_used, s.uploaded_at,
                s.contributor_user_id, u.username, s.camera_generation
            FROM scenes s
            LEFT JOIN users u ON u.id::TEXT = s.contributor_user_id
            WHERE {where_sql}
            ORDER BY {order} LIMIT :limit OFFSET :offset""",
            limit=limit, offset=offset, **params)
        conn.close()
        scenes = [{
            "id": str(r[0]), "country": r[1], "state": r[2], "region": r[3],
            "r2_key": r[4], "image_url": scene_public_url(r[4]),
            "quality_score": r[5], "quality_checked_at": str(r[6]) if r[6] else None,
            "quality_reason": r[7], "times_used": r[8], "uploaded_at": str(r[9]),
            "contributor_user_id": r[10], "contributor_username": r[11] or ("Unknown (deleted account)" if r[10] else "Anonymous"),
            "camera_generation": r[12],
        } for r in rows]
        return jsonify({"scenes": scenes, "total": total, "limit": limit, "offset": offset})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/scenes/recheck_quality", methods=["POST","OPTIONS"])
def admin_scenes_recheck_quality():
    """Runs the same AI quality checker that gates new uploads against
    ALREADY-uploaded scenes — either a specific list of scene_ids, or a
    batch of not-yet-checked ones. Capped per call to keep response
    times reasonable; the admin panel calls this repeatedly to work
    through a backlog."""
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err

    d = request.json or {}
    scene_ids = d.get("scene_ids") or []
    batch_unchecked = bool(d.get("unchecked_only"))
    batch_limit = min(int(d.get("limit") or 20), 10)

    try:
        conn = get_db()
        if scene_ids:
            rows = conn.run("SELECT id, r2_key, country FROM scenes WHERE id = ANY(:ids)", ids=scene_ids)
        elif batch_unchecked:
            rows = conn.run("""SELECT id, r2_key, country FROM scenes
                WHERE quality_checked_at IS NULL
                ORDER BY uploaded_at ASC LIMIT :lim""", lim=batch_limit)
        else:
            conn.close()
            return jsonify({"error": "Provide scene_ids or unchecked_only"}), 400

        results = []
        for scene_id, r2_key, scene_country in rows:
            b64 = get_storage_image_b64(r2_key)
            if not b64:
                results.append({"id": str(scene_id), "checked": False, "reason": "could not fetch image from storage"})
                continue
            passed, reason = ai_check_scene_quality(b64, country=scene_country)
            conn.run("""UPDATE scenes SET quality_score=:score, quality_checked_at=NOW(), quality_reason=:reason
                WHERE id=:id""", score=1 if passed else 0, reason=reason, id=scene_id)
            results.append({"id": str(scene_id), "checked": True, "passed": passed, "reason": reason})
        conn.close()

        passed_count = sum(1 for r in results if r.get("passed"))
        failed_count = sum(1 for r in results if r.get("checked") and not r.get("passed"))
        fetch_failed_count = sum(1 for r in results if not r.get("checked"))
        return jsonify({
            "results": results,
            "attempted": len(results),
            # "checked" now means genuinely evaluated (passed+failed) —
            # previously this counted every row pulled from the DB even
            # when the actual image couldn't be fetched from storage,
            # which silently made attempted/checked counts not add up
            # against passed+failed in the admin panel.
            "checked": passed_count + failed_count,
            "passed": passed_count,
            "failed": failed_count,
            "fetch_failed": fetch_failed_count,
        })
    except Exception as e:
        return safe_error(e)

@app.route("/admin/scenes/categorize_generation", methods=["POST","OPTIONS"])
def admin_scenes_categorize_generation():
    """Labels camera generation ONLY — genuinely separate from quality
    checking, using its own focused prompt (ai_estimate_camera_generation)
    rather than the combined one that turned out unreliable. Never
    touches quality_score/quality_checked_at, so running this doesn't
    flag anything for quality — a scene from a country/region only
    covered by gen-1 imagery gets correctly labeled 'Gen 1' without that
    being treated as a quality problem. Either a specific scene_ids
    list, or a batch of scenes with no generation label yet."""
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err

    d = request.json or {}
    scene_ids = d.get("scene_ids") or []
    batch_uncategorized = bool(d.get("uncategorized_only"))
    batch_limit = min(int(d.get("limit") or 20), 10)

    try:
        conn = get_db()
        if scene_ids:
            rows = conn.run("SELECT id, r2_key FROM scenes WHERE id = ANY(:ids)", ids=scene_ids)
        elif batch_uncategorized:
            rows = conn.run("""SELECT id, r2_key FROM scenes
                WHERE camera_generation IS NULL
                ORDER BY uploaded_at ASC LIMIT :lim""", lim=batch_limit)
        else:
            conn.close()
            return jsonify({"error": "Provide scene_ids or uncategorized_only"}), 400

        results = []
        for scene_id, r2_key in rows:
            b64 = get_storage_image_b64(r2_key)
            if not b64:
                results.append({"id": str(scene_id), "checked": False, "reason": "could not fetch image"})
                continue
            generation, raw = ai_estimate_camera_generation(b64)
            conn.run("UPDATE scenes SET camera_generation=:gen WHERE id=:id", gen=generation, id=scene_id)
            results.append({"id": str(scene_id), "checked": True, "generation": generation})
        conn.close()

        by_gen = {}
        for r in results:
            if r.get("checked"):
                by_gen[r["generation"]] = by_gen.get(r["generation"], 0) + 1
        return jsonify({"results": results, "checked": len(results), "by_generation": by_gen})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/scenes/delete/<scene_id>", methods=["DELETE","OPTIONS"])
def admin_scenes_delete(scene_id):
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    try:
        conn = get_db()
        rows = conn.run("SELECT r2_key FROM scenes WHERE id=:id", id=scene_id)
        if not rows:
            conn.close()
            return jsonify({"error": "Not found"}), 404
        r2_key = rows[0][0]
        conn.run("DELETE FROM scenes WHERE id=:id", id=scene_id)
        conn.close()
        try:
            import requests
            del_url = f"{SUPABASE_URL}/storage/v1/object/{STORAGE_BUCKET}/{r2_key}"
            requests.delete(del_url, headers={"Authorization": f"Bearer {SUPABASE_KEY}"}, timeout=15)
        except Exception as e:
            print("Storage delete error (row already removed):", e)
        return jsonify({"success": True})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/scenes/delete_bulk", methods=["POST","OPTIONS"])
def admin_scenes_delete_bulk():
    """Deletes several scenes in one call — both their Postgres rows and
    their actual files in Supabase Storage, using Storage's native
    multi-path delete endpoint (one request for all files, not one per
    file). Powers the Scene Library's multi-select delete."""
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    d = request.json or {}
    scene_ids = d.get("scene_ids") or []
    if not scene_ids:
        return jsonify({"error": "No scene_ids provided"}), 400
    try:
        conn = get_db()
        rows = conn.run("SELECT id, r2_key FROM scenes WHERE id = ANY(:ids)", ids=scene_ids)
        found_ids = [str(r[0]) for r in rows]
        r2_keys = [r[1] for r in rows]
        if found_ids:
            conn.run("DELETE FROM scenes WHERE id = ANY(:ids)", ids=found_ids)
        conn.close()

        if r2_keys:
            try:
                import requests
                del_url = f"{SUPABASE_URL}/storage/v1/object/{STORAGE_BUCKET}"
                requests.delete(
                    del_url,
                    headers={"Authorization": f"Bearer {SUPABASE_KEY}", "Content-Type": "application/json"},
                    json={"prefixes": r2_keys},
                    timeout=30
                )
            except Exception as e:
                print("Bulk storage delete error (rows already removed):", e)
        return jsonify({"success": True, "deleted": len(found_ids)})
    except Exception as e:
        return safe_error(e)

# ── Admin ─────────────────────────────────────────────────
def require_admin():
    """Returns (ok, error_response). Requires both the ADMIN_KEY (via X-Admin-Key
    header or 'key' query param for SSE) AND a valid session token (via X-Admin-Token
    header or 'token' query param for SSE). Keeping these out of the body means they
    never end up in server access logs."""
    if rate_limited("admin_check", client_ip(), max_attempts=60, window_seconds=60):
        return False, (jsonify({"error":"Too many requests"}), 429)
    # Accept from headers (normal requests) or query params (SSE — EventSource can't set headers)
    admin_key   = request.headers.get("X-Admin-Key")   or request.args.get("key", "")
    admin_token = request.headers.get("X-Admin-Token") or request.args.get("token", "")
    if not ADMIN_KEY or admin_key != ADMIN_KEY:
        return False, (jsonify({"error":"Forbidden"}), 403)
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
        urows = conn.run("SELECT username FROM users WHERE id=:uid", uid=user_id)
        target_username = urows[0][0] if urows else str(user_id)
        conn.run("UPDATE users SET disabled=:d WHERE id=:uid", d=disabled, uid=user_id)
        if disabled:
            conn.run("DELETE FROM sessions WHERE user_id=:uid", uid=user_id)
        conn.close()
        log_event("admin_disable" if disabled else "admin_enable", user_id=user_id, username=target_username, ip=client_ip())
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
        urows = conn.run("SELECT username FROM users WHERE id=:uid", uid=user_id)
        target_username = urows[0][0] if urows else str(user_id)
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
        log_event("admin_unban" if duration == "unban" else "admin_ban", user_id=user_id, username=target_username, detail=f"duration={duration} reason={reason}", ip=client_ip())
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
        urows = conn.run("SELECT username FROM users WHERE id=:uid", uid=user_id)
        target_username = urows[0][0] if urows else str(user_id)
        conn.run("DELETE FROM usage WHERE user_id=:uid", uid=user_id)
        conn.run("DELETE FROM sessions WHERE user_id=:uid", uid=user_id)
        conn.run("DELETE FROM users WHERE id=:uid", uid=user_id)
        conn.close()
        log_event("admin_delete_user", user_id=user_id, username=target_username, ip=client_ip())
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
        log_event("admin_reset_usage", user_id=user_id, ip=client_ip())
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
        log_event("admin_set_tier", user_id=user_id, detail=f"tier={tier} username={rows[0][0]}", ip=client_ip())
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
        rows  = conn.run("SELECT id,username,email,tier,created_at,last_login,banned_until,ban_reason,disabled,is_admin,email_verified,phone_number,phone_verified FROM users ORDER BY created_at DESC")
        conn.close()
        users = [{"id":r[0],"username":r[1],"email":r[2],"tier":r[3],
                  "created_at":str(r[4]),"last_login":str(r[5]),
                  "banned_until": str(r[6]) if r[6] else None,
                  "ban_reason": r[7], "disabled": bool(r[8]),
                  "is_admin": bool(r[9]), "email_verified": bool(r[10]),
                  "phone_number": r[11], "phone_verified": bool(r[12])} for r in rows]
        return jsonify({"users":users,"count":len(users)})
    except Exception as e:
        return safe_error(e)

@app.route("/ai/country_meta", methods=["POST", "OPTIONS"])
def ai_country_meta():
    """Return cached or AI-generated GeoGuessr meta guide for a country.
    Manual guides (written via admin panel) take priority over AI-generated ones."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    country = (d.get("country") or "").strip()
    iso     = (d.get("iso") or "").strip().upper()
    if not country:
        return jsonify({"error": "country required"}), 400

    try:
        conn = get_db()
        conn.run("""CREATE TABLE IF NOT EXISTS country_metas (
            iso TEXT PRIMARY KEY, country TEXT, content TEXT,
            source TEXT DEFAULT 'ai', last_edited_by TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW())""")
        rows = conn.run("SELECT content, source FROM country_metas WHERE iso=:iso", iso=iso)
        conn.close()
        if rows:
            data = _json.loads(rows[0][0])
            data['_source'] = rows[0][1] or 'ai'
            return jsonify(data)
    except Exception as e:
        print("country_meta cache error:", e)

    # No cached guide — generate with Claude
    prompt = f"""You are a world-class GeoGuessr expert. Generate a detailed meta guide for {country} in GeoGuessr.

Return ONLY valid JSON (no markdown, no backticks) in exactly this structure:
{{
  "dead_giveaway": "The single most reliable visual clue that immediately identifies this country",
  "visual_clues": [
    {{"icon":"🌱","title":"Vegetation","detail":"Description of typical plants/trees"}},
    {{"icon":"🛣️","title":"Roads","detail":"Road surface, markings, style"}},
    {{"icon":"🏠","title":"Architecture","detail":"Building styles visible from street"}},
    {{"icon":"🌄","title":"Terrain","detail":"Landscape and geography"}},
    {{"icon":"🚦","title":"Signs","detail":"Road sign style, language, colors"}}
  ],
  "landscape": "2-3 sentences on the typical landscape, terrain variety, climate zones",
  "road_meta": "2-3 sentences on road quality, markings, guardrail style, shoulder color",
  "language_signs": "What script/language appears on signs, any unique lettering",
  "vehicles": "Common car brands, license plate style, vehicle age typical",
  "easy_to_confuse": [
    {{"country":"Country Name","difference":"The ONE visual thing that separates them"}},
    {{"country":"Country Name 2","difference":"The ONE visual thing that separates them"}}
  ],
  "pro_tips": "2-3 advanced tips that top GeoGuessr players use to identify this country quickly"
}}"""

    try:
        result = call_claude([{"role":"user","content":prompt}], max_tokens=1200)
        clean = result.strip()
        if clean.startswith("```"): clean = "\n".join(clean.split("\n")[1:])
        if clean.endswith("```"):   clean = "\n".join(clean.split("\n")[:-1])
        data = _json.loads(clean)
        data['_source'] = 'ai'
        try:
            conn = get_db()
            conn.run("""INSERT INTO country_metas (iso, country, content, source)
                VALUES (:iso, :country, :content, 'ai')
                ON CONFLICT (iso) DO UPDATE SET content=:content, updated_at=NOW()
                WHERE country_metas.source='ai'""",
                iso=iso, country=country, content=_json.dumps(data))
            conn.close()
        except Exception as ce:
            print("Country meta cache save error:", ce)
        return jsonify(data)
    except Exception as e:
        return safe_error(e)

@app.route("/admin/upload_guide_image", methods=["POST","OPTIONS"])
def admin_upload_guide_image():
    """Upload a single image from the guide editor to Supabase Storage.
    Images are uploaded immediately when added to a block so the guide save
    payload only contains URLs, not base64 — essential for guides with
    20-30+ images which would otherwise exceed any reasonable request limit."""
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    d = request.json or {}
    image_b64 = d.get("image", "")
    iso = (d.get("iso") or "guide").strip().lower()
    if not image_b64:
        return jsonify({"error": "No image provided"}), 400
    try:
        if "," in image_b64:
            header, image_b64 = image_b64.split(",", 1)
            ext = "png" if "png" in header else "jpg"
        else:
            ext = "jpg"
        img_bytes = base64.b64decode(image_b64)
        r2_key = f"meta-guides/{iso}/{uuid.uuid4()}.{ext}"
        upload_url = f"{SUPABASE_URL}/storage/v1/object/scenes/{r2_key}"
        resp = http_requests.post(
            upload_url,
            headers={
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": f"image/{ext}",
                "x-upsert": "true"
            },
            data=img_bytes,
            timeout=30
        )
        if resp.status_code not in (200, 201):
            return jsonify({"error": f"Storage upload failed: {resp.status_code}"}), 500
        url = f"{SUPABASE_URL}/storage/v1/object/public/scenes/{r2_key}"
        return jsonify({"url": url})
    except Exception as e:
        return safe_error(e)

VALID_CAMERA_GENS = ["Gen 1", "Gen 2", "Gen 3", "Gen 4", "Trekker / Other"]

# Same coverage list used by region-map.html / the guide scaffold — used
# here purely to generate plausible wrong-answer options for the
# country-guessing training games.
QUIZ_COUNTRY_POOL = [
  "Albania","Andorra","Argentina","Australia","Austria","Bangladesh","Belgium",
  "Bhutan","Bolivia","Botswana","Brazil","Bulgaria","Cambodia","Canada","Chile",
  "Colombia","Costa Rica","Croatia","Cyprus","Czechia","Denmark",
  "Dominican Republic","Ecuador","Estonia","Eswatini","Finland","France",
  "Georgia","Germany","Ghana","Greece","Greenland","Guatemala","Hungary",
  "Iceland","India","Indonesia","Ireland","Israel","Italy","Japan","Jordan",
  "Kazakhstan","Kenya","Kyrgyzstan","Laos","Latvia","Lebanon","Lesotho",
  "Liechtenstein","Lithuania","Luxembourg","Madagascar","Malaysia","Malta",
  "Mexico","Monaco","Mongolia","Montenegro","Namibia","Nepal","Netherlands",
  "New Zealand","Nigeria","North Macedonia","Norway","Oman","Pakistan",
  "Palestine","Panama","Peru","Philippines","Poland","Portugal","Qatar",
  "Romania","Russia","Rwanda","San Marino","Sao Tome and Principe","Senegal",
  "Serbia","Singapore","Slovakia","Slovenia","South Africa","South Korea",
  "Spain","Sri Lanka","Sweden","Switzerland","Taiwan","Thailand","Tunisia",
  "Turkey","Uganda","Ukraine","United Arab Emirates","United Kingdom",
  "United States of America","Uruguay","Vietnam"
]
VALID_PHOTO_QUIZ_TYPES = ["bollard", "sign_shape", "vegetation", "license_plate"]

@app.route("/admin/camera_quiz/upload", methods=["POST","OPTIONS"])
def admin_camera_quiz_upload():
    """Uploads a labeled reference image for the Camera Generation training
    game. Real, correctly-labeled example photos have to come from an
    admin who can actually verify the generation — there's no way to
    safely auto-source these."""
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    d = request.json or {}
    image_b64 = d.get("image", "")
    correct_gen = (d.get("correct_gen") or "").strip()
    if not image_b64:
        return jsonify({"error": "No image provided"}), 400
    if correct_gen not in VALID_CAMERA_GENS:
        return jsonify({"error": f"correct_gen must be one of: {', '.join(VALID_CAMERA_GENS)}"}), 400
    try:
        if "," in image_b64:
            header, image_b64 = image_b64.split(",", 1)
            ext = "png" if "png" in header else "jpg"
        else:
            ext = "jpg"
        img_bytes = base64.b64decode(image_b64)
        r2_key = f"camera-quiz/{uuid.uuid4()}.{ext}"
        upload_url = f"{SUPABASE_URL}/storage/v1/object/scenes/{r2_key}"
        resp = http_requests.post(
            upload_url,
            headers={
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": f"image/{ext}",
                "x-upsert": "true"
            },
            data=img_bytes,
            timeout=30
        )
        if resp.status_code not in (200, 201):
            return jsonify({"error": f"Storage upload failed: {resp.status_code}"}), 500
        url = f"{SUPABASE_URL}/storage/v1/object/public/scenes/{r2_key}"

        conn = get_db()
        conn.run("""INSERT INTO camera_quiz_images (image_url, correct_gen)
            VALUES (:url, :gen)""", url=url, gen=correct_gen)
        conn.close()
        return jsonify({"success": True, "url": url})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/camera_quiz/list", methods=["GET","OPTIONS"])
def admin_camera_quiz_list():
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    try:
        conn = get_db()
        rows = conn.run("""SELECT id, image_url, correct_gen, created_at
            FROM camera_quiz_images ORDER BY created_at DESC""")
        conn.close()
        images = [{"id": str(r[0]), "image_url": r[1], "correct_gen": r[2], "created_at": str(r[3])} for r in rows]
        return jsonify({"images": images})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/camera_quiz/delete/<image_id>", methods=["DELETE","OPTIONS"])
def admin_camera_quiz_delete(image_id):
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    try:
        conn = get_db()
        conn.run("DELETE FROM camera_quiz_images WHERE id=:id", id=image_id)
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return safe_error(e)

@app.route("/camera_quiz/random", methods=["GET","OPTIONS"])
def camera_quiz_random():
    """Public — no login required, this is a free training game. Returns
    one random labeled image plus the fixed set of possible answers."""
    if request.method == "OPTIONS": return jsonify({}), 200
    try:
        conn = get_db()
        rows = conn.run("""SELECT id, image_url, correct_gen FROM camera_quiz_images
            ORDER BY RANDOM() LIMIT 1""")
        conn.close()
        if not rows:
            return jsonify({"error": "No quiz images available yet"}), 404
        return jsonify({
            "id": str(rows[0][0]),
            "image_url": rows[0][1],
            "correct_gen": rows[0][2],
            "options": VALID_CAMERA_GENS
        })
    except Exception as e:
        return safe_error(e)

@app.route("/admin/photo_quiz/upload", methods=["POST","OPTIONS"])
def admin_photo_quiz_upload():
    """Uploads a labeled photo for one of the country-guessing training
    games (Bollard Bingo, Sign Shape Sprint, Vegetation Snap, License Plate
    Guess) — all four share this same table/upload flow, distinguished
    only by quiz_type, since the game mechanic is identical for each."""
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    d = request.json or {}
    image_b64 = d.get("image", "")
    quiz_type = (d.get("quiz_type") or "").strip()
    correct_country = (d.get("correct_country") or "").strip()
    if not image_b64:
        return jsonify({"error": "No image provided"}), 400
    if quiz_type not in VALID_PHOTO_QUIZ_TYPES:
        return jsonify({"error": f"quiz_type must be one of: {', '.join(VALID_PHOTO_QUIZ_TYPES)}"}), 400
    if correct_country not in QUIZ_COUNTRY_POOL:
        return jsonify({"error": "correct_country must be a recognised GeoGuessr-covered country"}), 400
    try:
        if "," in image_b64:
            header, image_b64 = image_b64.split(",", 1)
            ext = "png" if "png" in header else "jpg"
        else:
            ext = "jpg"
        img_bytes = base64.b64decode(image_b64)
        r2_key = f"photo-quiz/{quiz_type}/{uuid.uuid4()}.{ext}"
        upload_url = f"{SUPABASE_URL}/storage/v1/object/scenes/{r2_key}"
        resp = http_requests.post(
            upload_url,
            headers={
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": f"image/{ext}",
                "x-upsert": "true"
            },
            data=img_bytes,
            timeout=30
        )
        if resp.status_code not in (200, 201):
            return jsonify({"error": f"Storage upload failed: {resp.status_code}"}), 500
        url = f"{SUPABASE_URL}/storage/v1/object/public/scenes/{r2_key}"

        conn = get_db()
        conn.run("""INSERT INTO photo_quiz_images (quiz_type, image_url, correct_country)
            VALUES (:qt, :url, :country)""", qt=quiz_type, url=url, country=correct_country)
        conn.close()
        return jsonify({"success": True, "url": url})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/photo_quiz/list", methods=["GET","OPTIONS"])
def admin_photo_quiz_list():
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    quiz_type = request.args.get("type", "")
    try:
        conn = get_db()
        if quiz_type:
            rows = conn.run("""SELECT id, quiz_type, image_url, correct_country, created_at
                FROM photo_quiz_images WHERE quiz_type=:qt ORDER BY created_at DESC""", qt=quiz_type)
        else:
            rows = conn.run("""SELECT id, quiz_type, image_url, correct_country, created_at
                FROM photo_quiz_images ORDER BY created_at DESC""")
        conn.close()
        images = [{"id": str(r[0]), "quiz_type": r[1], "image_url": r[2], "correct_country": r[3], "created_at": str(r[4])} for r in rows]
        return jsonify({"images": images})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/photo_quiz/delete/<image_id>", methods=["DELETE","OPTIONS"])
def admin_photo_quiz_delete(image_id):
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    try:
        conn = get_db()
        conn.run("DELETE FROM photo_quiz_images WHERE id=:id", id=image_id)
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return safe_error(e)

@app.route("/photo_quiz/random", methods=["GET","OPTIONS"])
def photo_quiz_random():
    """Public — no login required. Returns one random labeled photo of the
    requested quiz_type, plus 5 shuffled multiple-choice options (the
    correct country + 4 random decoys from the coverage pool)."""
    if request.method == "OPTIONS": return jsonify({}), 200
    quiz_type = request.args.get("type", "")
    if quiz_type not in VALID_PHOTO_QUIZ_TYPES:
        return jsonify({"error": f"type must be one of: {', '.join(VALID_PHOTO_QUIZ_TYPES)}"}), 400
    try:
        conn = get_db()
        rows = conn.run("""SELECT id, image_url, correct_country FROM photo_quiz_images
            WHERE quiz_type=:qt ORDER BY RANDOM() LIMIT 1""", qt=quiz_type)
        conn.close()
        if not rows:
            return jsonify({"error": "No quiz images available yet for this game"}), 404
        correct = rows[0][2]
        decoy_pool = [c for c in QUIZ_COUNTRY_POOL if c != correct]
        decoys = random.sample(decoy_pool, min(4, len(decoy_pool)))
        options = decoys + [correct]
        random.shuffle(options)
        return jsonify({
            "id": str(rows[0][0]),
            "image_url": rows[0][1],
            "correct_country": correct,
            "options": options
        })
    except Exception as e:
        return safe_error(e)

@app.route("/meta_quiz/random", methods=["GET","OPTIONS"])
def meta_quiz_random():
    """Meta Speed Quiz — pulls a random real fact directly out of an
    existing written guide's img-text/tip/warning blocks, and asks which
    country it describes. No new content to maintain — it reuses guides
    you've already written."""
    if request.method == "OPTIONS": return jsonify({}), 200
    try:
        conn = get_db()
        rows = conn.run("""SELECT country, content FROM country_metas
            WHERE source='manual' AND content IS NOT NULL""")
        conn.close()
        candidates = []
        for country, content in rows:
            try:
                blocks = _json.loads(content).get("blocks", [])
            except Exception:
                continue
            for b in blocks:
                if b.get("type") in ("img-text", "tip", "warning"):
                    text = (b.get("data") or {}).get("text", "").strip()
                    # Skip anything too short, or scaffold placeholder text
                    # that was never actually filled in.
                    if len(text) < 25 or "[" in text or "goes here" in text.lower():
                        continue
                    candidates.append({"country": country, "text": text})
        if not candidates:
            return jsonify({"error": "No guide facts available yet — write a few guides first"}), 404
        pick = random.choice(candidates)
        correct = pick["country"]
        decoy_pool = [c for c in QUIZ_COUNTRY_POOL if c != correct]
        decoys = random.sample(decoy_pool, min(4, len(decoy_pool)))
        options = decoys + [correct]
        random.shuffle(options)
        return jsonify({ "clue_text": pick["text"], "correct_country": correct, "options": options })
    except Exception as e:
        return safe_error(e)

@app.route("/daily_challenge", methods=["GET","OPTIONS"])
def daily_challenge():
    """One deterministic challenge per calendar day, the same for every
    player — combines all quiz pools (camera gen, the 4 photo-quiz types,
    and meta facts) so the daily pick can be any training format."""
    if request.method == "OPTIONS": return jsonify({}), 200
    try:
        today = datetime.date.today().isoformat()
        seed = int(hashlib.sha256(today.encode()).hexdigest(), 16)
        rnd = random.Random(seed)

        conn = get_db()
        camera_rows = conn.run("SELECT id, image_url, correct_gen FROM camera_quiz_images")
        photo_rows  = conn.run("SELECT id, quiz_type, image_url, correct_country FROM photo_quiz_images")
        conn.close()

        pool = []
        for r in camera_rows:
            pool.append({"kind": "camera_gen", "id": str(r[0]), "image_url": r[1], "answer": r[2], "options": VALID_CAMERA_GENS})
        for r in photo_rows:
            correct = r[3]
            decoy_pool = [c for c in QUIZ_COUNTRY_POOL if c != correct]
            decoys = rnd.sample(decoy_pool, min(4, len(decoy_pool)))
            opts = decoys + [correct]
            rnd.shuffle(opts)
            pool.append({"kind": r[1], "id": str(r[0]), "image_url": r[2], "answer": correct, "options": opts})

        if not pool:
            return jsonify({"error": "No challenge content available yet"}), 404

        pick = pool[seed % len(pool)]
        return jsonify({ "date": today, **pick })
    except Exception as e:
        return safe_error(e)

@app.route("/admin/country_meta", methods=["POST","OPTIONS"])
def admin_save_country_meta():
    """Save a manually written country guide. By save time all images have
    already been uploaded to Supabase Storage and replaced with URLs, so the
    content is just text/URLs and stays well within DB limits."""
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    d = request.json or {}
    iso     = (d.get("iso") or "").strip().upper()
    country = (d.get("country") or "").strip()
    content = d.get("content")
    if not iso or not country or not content:
        return jsonify({"error": "iso, country and content required"}), 400
    try:
        conn = get_db()
        conn.run("""CREATE TABLE IF NOT EXISTS country_metas (
            iso TEXT PRIMARY KEY, country TEXT, content TEXT,
            source TEXT DEFAULT 'ai', last_edited_by TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW())""")
        conn.run("""INSERT INTO country_metas (iso, country, content, source)
            VALUES (:iso, :country, :content, 'manual')
            ON CONFLICT (iso) DO UPDATE SET
                content=:content, source='manual', updated_at=NOW()""",
            iso=iso, country=country, content=_json.dumps(content))
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/country_meta/<iso>", methods=["DELETE","OPTIONS"])
def admin_delete_country_meta(iso):
    """Delete a country guide by ISO code."""
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    try:
        conn = get_db()
        conn.run("DELETE FROM country_metas WHERE iso=:iso", iso=iso.upper())
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/country_metas", methods=["GET","OPTIONS"])
def admin_list_country_metas():
    """List all saved country guides for the admin panel."""
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    try:
        conn = get_db()
        rows = conn.run("SELECT iso, country, source, updated_at FROM country_metas ORDER BY country ASC")
        conn.close()
        return jsonify({"guides": [{"iso":r[0],"country":r[1],"source":r[2],"updated_at":str(r[3])} for r in rows]})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/dashboard", methods=["GET","OPTIONS"])
def admin_dashboard():
    """Single endpoint that returns everything the admin panel needs on load:
    stats, users, and recent logs. One round-trip instead of 4."""
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    try:
        conn = get_db()
        # Stats
        total = conn.run("SELECT COUNT(*) FROM users")[0][0]
        pro   = conn.run("SELECT COUNT(*) FROM users WHERE tier='pro'")[0][0]
        today_rows = conn.run("""SELECT COALESCE(SUM(analyses),0), COALESCE(SUM(f7_captures),0),
            COALESCE(SUM(teachings),0) FROM usage WHERE date=CURRENT_DATE""")
        today_analyses = today_rows[0][0] if today_rows else 0
        today_f7       = today_rows[0][1] if today_rows else 0
        today_teachings= today_rows[0][2] if today_rows else 0
        scene_count = conn.run("SELECT COUNT(*) FROM scenes")[0][0]
        usage_today = conn.run("""SELECT u.username, u.tier, us.f7_captures, us.teachings, us.analyses
            FROM usage us JOIN users u ON u.id=us.user_id
            WHERE us.date=CURRENT_DATE ORDER BY (us.analyses+us.f7_captures+us.teachings) DESC LIMIT 20""")
        # Users
        users = conn.run("""SELECT u.id,u.username,u.email,u.tier,u.created_at,
            u.banned_until,u.ban_reason,u.email_verified,u.disabled,u.is_admin,
            u.last_login FROM users u ORDER BY u.created_at DESC""")
        # Recent activity logs
        logs = conn.run("""SELECT event_type, user_id, username, detail, ip, created_at
            FROM activity_logs ORDER BY created_at DESC LIMIT 200""")
        # Recent chat logs
        chats = conn.run("""SELECT username, correct_location, guessed_location,
            user_message, ai_reply, created_at
            FROM chat_logs ORDER BY created_at DESC LIMIT 100""")
        conn.close()
    except Exception as e:
        return safe_error(e)

    return jsonify({
        "stats": {
            "total_users": total, "pro_users": pro,
            "today_analyses": today_analyses, "today_f7": today_f7,
            "today_teachings": today_teachings, "scene_count": scene_count,
            "usage_today": [{"username":r[0],"tier":r[1],"f7":r[2],"guides":r[3],"analyses":r[4]} for r in usage_today]
        },
        "users": [{"id":r[0],"username":r[1],"email":r[2],"tier":r[3],
                   "created_at":str(r[4]),"banned_until":str(r[5]) if r[5] else None,
                   "ban_reason":r[6],"email_verified":r[7],"disabled":r[8],
                   "is_admin":r[9],"last_login":str(r[10]) if r[10] else None} for r in users],
        "logs": [{"event_type":r[0],"user_id":r[1],"username":r[2],
                  "detail":r[3],"ip":r[4],"created_at":str(r[5])} for r in logs],
        "chats": [{"username":r[0],"correct_location":r[1],"guessed_location":r[2],
                   "user_message":r[3],"ai_reply":r[4],"created_at":str(r[5])} for r in chats]
    })

@app.route("/admin/poll", methods=["GET","OPTIONS"])
def admin_poll():
    """Lightweight incremental poll — only returns activity_log rows newer
    than the 'since' timestamp. Called every 3 seconds by the admin panel.
    Returns almost nothing when idle, so it's fast and cheap."""
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    since = request.args.get("since", "")
    try:
        conn = get_db()
        if since:
            rows = conn.run("""SELECT event_type, user_id, username, detail, ip, created_at
                FROM activity_logs WHERE created_at > :since
                ORDER BY created_at ASC""", since=since)
        else:
            rows = conn.run("""SELECT event_type, user_id, username, detail, ip, created_at
                FROM activity_logs ORDER BY created_at DESC LIMIT 1""")
        conn.close()
        events = [{"event_type":r[0],"user_id":r[1],"username":r[2],
                   "detail":r[3],"ip":r[4],"created_at":str(r[5])} for r in rows]
        return jsonify({"events": events})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/activity_logs", methods=["GET","OPTIONS"])
def admin_activity_logs():
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    limit     = min(int(request.args.get("limit", 200)), 1000)
    event_type = request.args.get("type", "")
    try:
        conn = get_db()
        if event_type:
            rows = conn.run("""SELECT event_type, user_id, username, detail, ip, created_at
                FROM activity_logs WHERE event_type=:t
                ORDER BY created_at DESC LIMIT :limit""", t=event_type, limit=limit)
        else:
            rows = conn.run("""SELECT event_type, user_id, username, detail, ip, created_at
                FROM activity_logs ORDER BY created_at DESC LIMIT :limit""", limit=limit)
        conn.close()
        logs = [{"event_type": r[0], "user_id": r[1], "username": r[2],
                 "detail": r[3], "ip": r[4], "created_at": str(r[5])} for r in rows]
        return jsonify({"logs": logs, "count": len(logs)})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/chat_logs", methods=["GET","OPTIONS"])
def admin_chat_logs():
    if request.method == "OPTIONS": return jsonify({}), 200
    ok, err = require_admin()
    if not ok: return err
    limit = min(int(request.args.get("limit", 100)), 500)
    try:
        conn = get_db()
        rows = conn.run("""SELECT username, correct_location, guessed_location,
            user_message, ai_reply, created_at
            FROM chat_logs ORDER BY created_at DESC LIMIT :limit""", limit=limit)
        conn.close()
        logs = [{"username": r[0], "correct_location": r[1], "guessed_location": r[2],
                 "user_message": r[3], "ai_reply": r[4], "created_at": str(r[5])} for r in rows]
        return jsonify({"logs": logs, "count": len(logs)})
    except Exception as e:
        return safe_error(e)
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

@app.route("/admin/resend_phone_verification", methods=["POST","OPTIONS"])
def admin_resend_phone_verification():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    ok, err = require_admin()
    if not ok: return err
    user_id = d.get("user_id")
    if not user_id:
        return jsonify({"error":"user_id required"}),400
    try:
        conn = get_db()
        rows = conn.run("SELECT username,phone_number,phone_verified FROM users WHERE id=:uid", uid=user_id)
        conn.close()
        if not rows:
            return jsonify({"error":"User not found"}),404
        username, phone_number, verified = rows[0]
        if verified:
            return jsonify({"error":"User is already phone-verified"}),400
        if not phone_number:
            return jsonify({"error":"This account has no phone number on file"}),400
        if not TWILIO_CONFIGURED:
            return jsonify({"error":"Twilio is not configured on the server"}),503
        if not send_phone_verification(phone_number):
            return jsonify({"error":"Couldn't send SMS right now. Please try again shortly."}),502
        log_event("admin_resend_phone", user_id=user_id, username=username, ip=client_ip())
        return jsonify({"success": True})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/set_phone_verified", methods=["POST","OPTIONS"])
def admin_set_phone_verified():
    """Manually mark (or unmark) an account's phone as verified — for support
    cases where SMS delivery is unreliable (e.g. certain countries/carriers)
    and an admin has confirmed the number by other means."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    ok, err = require_admin()
    if not ok: return err
    user_id  = d.get("user_id")
    verified = bool(d.get("verified", True))
    if not user_id:
        return jsonify({"error":"user_id required"}),400
    try:
        conn = get_db()
        urows = conn.run("SELECT username FROM users WHERE id=:uid", uid=user_id)
        if not urows:
            conn.close(); return jsonify({"error":"User not found"}),404
        target_username = urows[0][0]
        conn.run("UPDATE users SET phone_verified=:v WHERE id=:uid", v=verified, uid=user_id)
        conn.close()
        log_event("admin_set_phone_verified", user_id=user_id, username=target_username,
                   detail=f"verified={verified}", ip=client_ip())
        return jsonify({"success": True, "phone_verified": verified})
    except Exception as e:
        return safe_error(e)

@app.route("/admin/set_phone_number", methods=["POST","OPTIONS"])
def admin_set_phone_number():
    """Add or correct a user's phone number from the admin panel. Setting a
    new number resets phone_verified to False (a new number hasn't been
    proven to belong to this user yet) unless verified=True is passed
    explicitly alongside it."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    ok, err = require_admin()
    if not ok: return err
    user_id      = d.get("user_id")
    phone_number = (d.get("phone_number") or "").strip()
    mark_verified = bool(d.get("verified", False))
    if not user_id:
        return jsonify({"error":"user_id required"}),400
    if not is_valid_e164(phone_number):
        return jsonify({"error":"Enter a valid phone number in international format, e.g. +61412345678"}),400
    try:
        conn = get_db()
        urows = conn.run("SELECT username FROM users WHERE id=:uid", uid=user_id)
        if not urows:
            conn.close(); return jsonify({"error":"User not found"}),404
        target_username = urows[0][0]
        conn.run("UPDATE users SET phone_number=:p, phone_verified=:v WHERE id=:uid",
                  p=phone_number, v=mark_verified, uid=user_id)
        conn.close()
        log_event("admin_set_phone_number", user_id=user_id, username=target_username,
                   detail=f"phone={phone_number}", ip=client_ip())
        return jsonify({"success": True, "phone_number": phone_number, "phone_verified": mark_verified})
    except Exception as e:
        err = str(e)
        if "unique" in err.lower():
            return jsonify({"error":"This phone number is already registered to another account"}),409
        return safe_error(e)

@app.route("/admin/reset_phone", methods=["POST","OPTIONS"])
def admin_reset_phone():
    """Clears a user's phone number and resets phone_verified to False —
    e.g. for a number that was entered wrong, is no longer theirs, or needs
    a completely fresh start. Since the login gate only blocks when a
    phone_number is on file (see login()), clearing both together rather
    than just the verified flag avoids leaving the account in a locked-out
    state where it has an unverified number it has no way to fix itself."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    ok, err = require_admin()
    if not ok: return err
    user_id = d.get("user_id")
    if not user_id:
        return jsonify({"error":"user_id required"}),400
    try:
        conn = get_db()
        urows = conn.run("SELECT username FROM users WHERE id=:uid", uid=user_id)
        if not urows:
            conn.close(); return jsonify({"error":"User not found"}),404
        target_username = urows[0][0]
        conn.run("UPDATE users SET phone_number=NULL, phone_verified=FALSE WHERE id=:uid", uid=user_id)
        conn.close()
        log_event("admin_reset_phone", user_id=user_id, username=target_username, ip=client_ip())
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
