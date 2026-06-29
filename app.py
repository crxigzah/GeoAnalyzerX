"""
GeoAnalyzerX Platform API — v2.0 with Cloud Scene Library (Cloudflare R2)
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib, os, secrets, uuid, base64, io
import pg8000.native
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app, origins=["*"], supports_credentials=True)

# ── Config ────────────────────────────────────────────────
DATABASE_URL           = os.environ.get("DATABASE_URL", "")
ADMIN_KEY              = os.environ.get("ADMIN_KEY", "")
FRONTEND_URL           = os.environ.get("FRONTEND_URL", "https://geoanalyzerx.netlify.app")
CF_ACCOUNT_ID          = os.environ.get("CF_ACCOUNT_ID", "")
CF_R2_ACCESS_KEY       = os.environ.get("CF_R2_ACCESS_KEY", "")
CF_R2_SECRET_KEY       = os.environ.get("CF_R2_SECRET_KEY", "")
CF_R2_BUCKET           = os.environ.get("CF_R2_BUCKET", "geoanalyzerx-scenes")
CF_R2_PUBLIC_URL       = os.environ.get("CF_R2_PUBLIC_URL", "")  # optional public bucket URL

# ── Stripe ────────────────────────────────────────────────
import stripe
import pyotp, qrcode, io as _io, base64 as _b64

stripe.api_key          = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET   = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRO_PRICE_ID     = os.environ.get("STRIPE_PRO_PRICE_ID", "")

print(f"Stripe key loaded: {'YES' if stripe.api_key else 'MISSING'}")
print(f"Stripe price ID:   {'YES' if STRIPE_PRO_PRICE_ID else 'MISSING'}")
print(f"Stripe webhook:    {'YES' if STRIPE_WEBHOOK_SECRET else 'MISSING'}")
print(f"R2 configured:     {'YES' if CF_R2_ACCESS_KEY else 'MISSING'}")

@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Auth-Token'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

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
        conn.run("CREATE INDEX IF NOT EXISTS idx_scenes_state ON scenes(state)")
        conn.run("CREATE INDEX IF NOT EXISTS idx_scenes_country_region ON scenes(country, region)")
        conn.close()
        print("DB init OK")
    except Exception as e:
        print("DB init error:", e)

def hp(p): return hashlib.sha256(p.encode()).hexdigest()

# ── R2 / S3 helpers ───────────────────────────────────────
def get_r2_client():
    """Get boto3 S3 client pointed at Cloudflare R2."""
    try:
        import boto3
        return boto3.client(
            's3',
            endpoint_url=f'https://{CF_ACCOUNT_ID}.r2.cloudflarestorage.com',
            aws_access_key_id=CF_R2_ACCESS_KEY,
            aws_secret_access_key=CF_R2_SECRET_KEY,
            region_name='auto'
        )
    except Exception as e:
        print("R2 client error:", e)
        return None

def upload_to_r2(image_b64: str, country: str, state: str, region: str) -> str | None:
    """Upload a base64 JPEG to R2, return the object key."""
    try:
        s3 = get_r2_client()
        if not s3:
            return None
        image_bytes = base64.b64decode(image_b64)
        key = f"scenes/{country}/{state or 'unknown'}/{region or 'central'}/{uuid.uuid4()}.jpg"
        s3.put_object(
            Bucket=CF_R2_BUCKET,
            Key=key,
            Body=image_bytes,
            ContentType='image/jpeg'
        )
        return key
    except Exception as e:
        print("R2 upload error:", e)
        return None

def get_r2_image_b64(key: str) -> str | None:
    """Fetch an image from R2 and return as base64."""
    try:
        # If public URL is configured, fetch directly
        if CF_R2_PUBLIC_URL:
            import urllib.request
            url = f"{CF_R2_PUBLIC_URL.rstrip('/')}/{key}"
            with urllib.request.urlopen(url, timeout=5) as resp:
                return base64.b64encode(resp.read()).decode()
        # Otherwise use signed URL via boto3
        s3 = get_r2_client()
        if not s3:
            return None
        obj = s3.get_object(Bucket=CF_R2_BUCKET, Key=key)
        return base64.b64encode(obj['Body'].read()).decode()
    except Exception as e:
        print("R2 fetch error:", e)
        return None

def classify_region(lat, lng, state):
    """Classify lat/lng into a broad region quadrant."""
    if not lat or not lng:
        return 'central'
    # Use state centroid for quadrant calculation
    STATE_CENTRES = {
        'victoria': (-37.0, 144.0), 'queensland': (-22.0, 144.0),
        'new south wales': (-32.0, 146.0), 'south australia': (-30.0, 135.0),
        'western australia': (-25.0, 121.0), 'northern territory': (-19.0, 133.0),
        'tasmania': (-42.0, 146.5),
    }
    centre = STATE_CENTRES.get((state or '').lower(), (-25.0, 133.0))
    ns = 'north' if lat > centre[0] else 'south'
    ew = 'east'  if lng > centre[1] else 'west'
    return f"{ns}{ew}"

# ── Health ────────────────────────────────────────────────
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
    if len(username)<3: return jsonify({"error":"Username must be at least 3 characters"}),400
    if "@" not in email: return jsonify({"error":"Invalid email"}),400
    if len(password)<6: return jsonify({"error":"Password must be at least 6 characters"}),400
    try:
        conn  = get_db()
        rows  = conn.run(
            "INSERT INTO users (username,email,password) VALUES (:u,:e,:p) RETURNING id,username,email,tier",
            u=username, e=email, p=hp(password))
        user  = {"id":rows[0][0],"username":rows[0][1],"email":rows[0][2],"tier":rows[0][3]}
        token = secrets.token_urlsafe(32)
        conn.run("INSERT INTO sessions (token,user_id) VALUES (:t,:uid)", t=token, uid=user["id"])
        conn.close()
        return jsonify({"token":token,"user":user}), 201
    except Exception as e:
        err = str(e)
        if "unique" in err.lower(): return jsonify({"error":"Username or email already taken"}),409
        return jsonify({"error": err}), 500

@app.route("/auth/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    email    = d.get("email","").strip().lower()
    password = d.get("password","")
    try:
        conn = get_db()
        rows = conn.run("SELECT id,username,email,tier FROM users WHERE email=:e AND password=:p",
                        e=email, p=hp(password))
        if not rows:
            conn.close(); return jsonify({"error":"Invalid email or password"}),401
        user  = {"id":rows[0][0],"username":rows[0][1],"email":rows[0][2],"tier":rows[0][3]}
        token = secrets.token_urlsafe(32)
        conn.run("INSERT INTO sessions (token,user_id) VALUES (:t,:uid)", t=token, uid=user["id"])
        conn.run("UPDATE users SET last_login=NOW() WHERE id=:uid", uid=user["id"])
        conn.close()
        return jsonify({"token":token,"user":user})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/auth/verify", methods=["POST", "OPTIONS"])
def verify():
    if request.method == "OPTIONS": return jsonify({}), 200
    token = (request.json or {}).get("token","")
    if not token: return jsonify({"valid":False}),401
    try:
        conn = get_db()
        rows = conn.run("""SELECT u.id,u.username,u.email,u.tier FROM users u
            JOIN sessions s ON s.user_id=u.id
            WHERE s.token=:t AND s.expires_at>NOW()""", t=token)
        conn.close()
        if not rows: return jsonify({"valid":False}),401
        user = {"id":rows[0][0],"username":rows[0][1],"email":rows[0][2],"tier":rows[0][3]}
        return jsonify({"valid":True,"user":user})
    except Exception as e:
        return jsonify({"valid":False,"error":str(e)}),500

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
        return jsonify({"error": str(e)}), 500
    if hp(current) != pwd_hash:
        return jsonify({"error": "Current password is incorrect"}), 400
    try:
        conn = get_db()
        conn.run("UPDATE users SET password=:p WHERE id=:uid", p=hp(new_pwd), uid=user_id)
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
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
        return jsonify({"error": str(e)}), 500
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
        return jsonify({"error": str(e)}), 500
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
        return jsonify({"error": str(e)}), 500
    if not pending: return jsonify({"error": "No pending 2FA setup"}), 400
    if not pyotp.TOTP(pending).verify(code, valid_window=1):
        return jsonify({"error": "Incorrect code — try again"}), 400
    try:
        conn = get_db()
        conn.run("UPDATE users SET totp_secret=:s, totp_enabled=TRUE, totp_secret_pending=NULL WHERE id=:uid",
                 s=pending, uid=user_id)
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
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
        return jsonify({"error": str(e)}), 500
    if not secret: return jsonify({"error": "2FA not enabled"}), 400
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return jsonify({"error": "Incorrect code"}), 400
    try:
        conn = get_db()
        conn.run("UPDATE users SET totp_secret=NULL, totp_enabled=FALSE WHERE id=:uid", uid=user_id)
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"disabled": True})

# ── Scene Library (Cloud) ─────────────────────────────────
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
    token     = d.get("token", "")  # optional — for contributor tracking

    if not image_b64 or not country:
        return jsonify({"error": "image and country required"}), 400

    if not CF_R2_ACCESS_KEY:
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
        return jsonify({"error": str(e)}), 500

    return jsonify({"uploaded": True, "region": region, "key": r2_key})

@app.route("/scenes/refs", methods=["POST", "OPTIONS"])
def get_refs():
    """Get up to N reference scene images for a given state/country."""
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    state   = (d.get("state") or "").strip()
    country = (d.get("country") or "").strip()
    region  = (d.get("region") or "").strip()
    limit   = min(int(d.get("limit", 5)), 8)

    if not state and not country:
        return jsonify({"error": "state or country required"}), 400

    try:
        conn = get_db()
        if state and region:
            # Prefer same region, then fall back to any region in state
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
        return jsonify({"error": str(e)}), 500

    if not rows:
        return jsonify({"images": [], "count": 0})

    # Fetch images from R2 in parallel (simple sequential for now)
    images = []
    for r2_key, region_name, score in rows:
        b64 = get_r2_image_b64(r2_key)
        if b64:
            images.append({"b64": b64, "region": region_name, "quality_score": score})

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
        return jsonify({"error": str(e)}), 500

# ── Admin ─────────────────────────────────────────────────
@app.route("/admin/set_tier", methods=["POST","OPTIONS"])
def admin_set_tier():
    if request.method == "OPTIONS": return jsonify({}), 200
    d = request.json or {}
    if not ADMIN_KEY or d.get("admin_key") != ADMIN_KEY:
        return jsonify({"error":"Forbidden"}),403
    email = d.get("email","").strip().lower()
    tier  = d.get("tier","free")
    if tier not in ("free","pro","beta"): return jsonify({"error":"Invalid tier"}),400
    try:
        conn = get_db()
        rows = conn.run("UPDATE users SET tier=:tier WHERE email=:e RETURNING username,email,tier",
                        tier=tier, e=email)
        conn.close()
        if not rows: return jsonify({"error":"User not found"}),404
        return jsonify({"updated":{"username":rows[0][0],"email":rows[0][1],"tier":rows[0][2]}})
    except Exception as e:
        return jsonify({"error":str(e)}),500

@app.route("/admin/users", methods=["GET","OPTIONS"])
def admin_users():
    if request.method == "OPTIONS": return jsonify({}), 200
    if not ADMIN_KEY or request.args.get("admin_key") != ADMIN_KEY:
        return jsonify({"error":"Forbidden"}),403
    try:
        conn  = get_db()
        rows  = conn.run("SELECT id,username,email,tier,created_at,last_login FROM users ORDER BY created_at DESC")
        conn.close()
        users = [{"id":r[0],"username":r[1],"email":r[2],"tier":r[3],
                  "created_at":str(r[4]),"last_login":str(r[5])} for r in rows]
        return jsonify({"users":users,"count":len(users)})
    except Exception as e:
        return jsonify({"error":str(e)}),500

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
        return jsonify({"error": str(e)}), 500
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
        return jsonify({"error": str(e)}), 500

@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data()
    sig     = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
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
