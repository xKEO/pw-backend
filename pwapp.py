from pathlib import Path
from dotenv import load_dotenv
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, abort, g
from flask_cors import CORS
import mysql.connector
from mysql.connector import Error as MySQLError
import bcrypt
import os
import logging
from functools import wraps
import jwt
import hashlib
import secrets
import stripe
import re

app = Flask(__name__)
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False

# ---------- CORS ----------
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "https://passwordmanager.tech").split(",")
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# ---------- Helpers / Env ----------

def _require_env(name: str) -> str:
    val = os.getenv(name)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=_require_env("DB_USER"),
        password=_require_env("DB_PASSWORD"),
        database=_require_env("DB_NAME"),
    )

# ---------- JWT Config ----------

JWT_SECRET = _require_env("JWT_SECRET")
JWT_ALGO = os.getenv("JWT_ALGO", "HS256")
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", "60"))
JWT_ISSUER = os.getenv("JWT_ISSUER", "passwordmanager-api")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "passwordmanager-clients")

# ---------- Refresh Token Config ----------
REFRESH_EXP_DAYS = int(os.getenv("REFRESH_EXP_DAYS", "30"))

# ---------- Stripe Config ----------
STRIPE_SECRET_KEY = _require_env("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = _require_env("STRIPE_WEBHOOK_SECRET")
STRIPE_PRICE_ID = _require_env("STRIPE_PRICE_ID")  # Your $19 one-time price ID
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://passwordmanager.tech")

stripe.api_key = STRIPE_SECRET_KEY

# ---------- Download Config ----------
DOWNLOAD_URL = os.getenv("DOWNLOAD_URL", "https://github.com/yourusername/repo/releases/latest/download/PasswordManager.zip")

# ---------- Validation ----------

def validate_username(username: str) -> tuple[bool, str]:
    if not username:
        return False, "Username is required"
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 50:
        return False, "Username must be less than 50 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, ""

def validate_email(email: str) -> tuple[bool, str]:
    if not email:
        return False, "Email is required"
    if len(email) > 255:
        return False, "Email is too long"
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return False, "Invalid email format"
    return True, ""

def validate_password(password: str) -> tuple[bool, str]:
    if not password:
        return False, "Password is required"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if len(password) > 128:
        return False, "Password is too long"
    return True, ""

# ---------- JWT Helpers ----------

def create_access_token(uid: int, username: str, has_purchased: bool) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(uid),
        "username": username,
        "purchased": has_purchased,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def jwt_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify(success=False, message="Missing or invalid Authorization header"), 401

        token = auth_header.split(" ", 1)[1].strip()
        try:
            payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[JWT_ALGO],
                audience=JWT_AUDIENCE,
                issuer=JWT_ISSUER,
            )
        except jwt.ExpiredSignatureError:
            return jsonify(success=False, message="Token expired"), 401
        except jwt.InvalidTokenError:
            return jsonify(success=False, message="Invalid token"), 401

        g.jwt_payload = payload
        g.current_uid = int(payload.get("sub", 0))
        g.current_username = payload.get("username")
        g.current_has_purchased = payload.get("purchased", False)

        return fn(*args, **kwargs)
    return wrapper

# ---------- Utility Helpers ----------

def generate_refresh_token() -> tuple[str, str]:
    raw = secrets.token_hex(32)
    hashed = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return raw, hashed

def generate_license_key() -> str:
    """Generate a license key like XXXX-XXXX-XXXX-XXXX"""
    segments = []
    for _ in range(4):
        segment = secrets.token_hex(2).upper()
        segments.append(segment)
    return "-".join(segments)

def check_user_purchased(cur, uid: int) -> bool:
    cur.execute(
        """
        SELECT id FROM pm_purchases 
        WHERE user_id = %s AND status = 'completed' 
        LIMIT 1
        """,
        (uid,)
    )
    return cur.fetchone() is not None

# ---------- Error Handlers ----------

@app.errorhandler(400)
def _bad_request(e):
    return jsonify(success=False, message=str(e.description or "Bad request")), 400

@app.errorhandler(401)
def _unauth(e):
    return jsonify(success=False, message=str(e.description or "Unauthorized")), 401

@app.errorhandler(403)
def _forbidden(e):
    return jsonify(success=False, message=str(e.description or "Forbidden")), 403

@app.errorhandler(404)
def _not_found(e):
    return jsonify(success=False, message=str(e.description or "Not found")), 404

@app.errorhandler(500)
def _server_error(e):
    return jsonify(success=False, message="Server error"), 500

# ---------- Health Checks ----------

@app.route("/api/ping")
def ping():
    return jsonify(ok=True)

@app.route("/api/health")
def health():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        cur.close()
        conn.close()
        return jsonify(ok=True, db=True)
    except Exception as ex:
        app.logger.exception("[HEALTH] DB check failed")
        return jsonify(ok=False, db=False, error=str(ex)), 500

# ---------- AUTH: LOGIN (HttpOnly refresh cookie) ----------

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True) or {}

    username_or_email = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username_or_email or not password:
        return jsonify(success=False, message="Username and password required"), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            """
            SELECT uid, username, email, password, is_active
            FROM pm_users
            WHERE username = %s OR email = %s
            LIMIT 1
            """,
            (username_or_email, username_or_email.lower())
        )
        user = cur.fetchone()

        if not user:
            return jsonify(success=False, message="Invalid username or password"), 401
        if not user.get("is_active"):
            return jsonify(success=False, message="Account is disabled"), 403

        stored_hash = user.get("password") or ""
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode("utf-8")

        try:
            if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
                return jsonify(success=False, message="Invalid username or password"), 401
        except Exception:
            app.logger.exception("[LOGIN] bcrypt error")
            return jsonify(success=False, message="Invalid username or password"), 401

        uid = int(user["uid"])
        has_purchased = check_user_purchased(cur, uid)

        # create refresh token (raw + sha256 hash)
        raw_refresh, hashed_refresh = generate_refresh_token()
        expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_EXP_DAYS)

        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        user_agent = (request.headers.get("User-Agent") or "")[:255]

        cur.execute(
            """
            INSERT INTO pm_refresh_tokens
                (user_id, refresh_token_hash, expires_at, ip_address, user_agent, created_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
            """,
            (uid, hashed_refresh, expires_at, ip_address, user_agent)
        )
        conn.commit()

        access_token = create_access_token(uid, user["username"], has_purchased)

        resp = jsonify(
            success=True,
            uid=uid,
            username=user["username"],
            email=user["email"],
            has_purchased=has_purchased,
            access_token=access_token,
            access_expires_in=JWT_EXP_MINUTES * 60,
            refresh_expires_in=REFRESH_EXP_DAYS * 86400,
        )

        # IMPORTANT: passwordmanager.tech -> api.passwordmanager.tech is cross-site
        # Browsers require SameSite=None + Secure for cookies to be sent.
        resp.set_cookie(
            "pm_refresh",
            raw_refresh,
            httponly=True,
            secure=True,
            samesite="None",
            max_age=REFRESH_EXP_DAYS * 86400,
            path="/api/auth",   # cookie only sent to /api/auth/*
        )

        return resp, 200

    except MySQLError:
        app.logger.exception("[LOGIN] MySQL error")
        return jsonify(success=False, message="Service unavailable"), 503
    except Exception:
        app.logger.exception("[LOGIN] Unhandled error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# ---------- AUTH: REGISTER ----------

@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    password2 = data.get("password2") or ""

    # Validate inputs
    valid, msg = validate_username(username)
    if not valid:
        return jsonify(success=False, message=msg), 400

    valid, msg = validate_email(email)
    if not valid:
        return jsonify(success=False, message=msg), 400

    valid, msg = validate_password(password)
    if not valid:
        return jsonify(success=False, message=msg), 400

    if password != password2:
        return jsonify(success=False, message="Passwords do not match"), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        # Check if username exists
        cur.execute("SELECT uid FROM pm_users WHERE username = %s LIMIT 1", (username,))
        if cur.fetchone():
            return jsonify(success=False, message="Username already taken"), 409

        # Check if email exists
        cur.execute("SELECT uid FROM pm_users WHERE email = %s LIMIT 1", (email,))
        if cur.fetchone():
            return jsonify(success=False, message="Email already registered"), 409

        # Hash password
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        # Insert user
        cur.execute(
            """
            INSERT INTO pm_users (username, email, password, is_active, is_verified, created_at)
            VALUES (%s, %s, %s, 1, 0, NOW())
            """,
            (username, email, password_hash)
        )
        conn.commit()

        uid = cur.lastrowid
        app.logger.info(f"[REGISTER] New user registered: {username} (uid={uid})")

        return jsonify(success=True, message="Account created successfully", uid=uid), 201

    except MySQLError:
        app.logger.exception("[REGISTER] MySQL error")
        return jsonify(success=False, message="Service unavailable"), 503
    except Exception:
        app.logger.exception("[REGISTER] Unhandled error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


# ---------- AUTH: REFRESH (HttpOnly cookie flow) ----------

@app.route("/api/auth/refresh", methods=["POST"])
def auth_refresh():
    raw_refresh = (request.cookies.get("pm_refresh") or "").strip()
    if not raw_refresh:
        return jsonify(success=False, message="Refresh token required"), 400

    hashed_refresh = hashlib.sha256(raw_refresh.encode("utf-8")).hexdigest()

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            """
            SELECT t.id, t.user_id, t.expires_at, t.revoked_at,
                   u.username, u.email, u.is_active
            FROM pm_refresh_tokens t
            JOIN pm_users u ON u.uid = t.user_id
            WHERE t.refresh_token_hash = %s
            LIMIT 1
            """,
            (hashed_refresh,)
        )
        row = cur.fetchone()

        if not row:
            resp = jsonify(success=False, message="Invalid refresh token")
            resp.set_cookie("pm_refresh", "", expires=0, path="/api/auth",
                            httponly=True, secure=True, samesite="None")
            return resp, 401

        if row["revoked_at"] is not None:
            resp = jsonify(success=False, message="Refresh token revoked")
            resp.set_cookie("pm_refresh", "", expires=0, path="/api/auth",
                            httponly=True, secure=True, samesite="None")
            return resp, 401

        now = datetime.now(timezone.utc)
        exp = row["expires_at"]
        if isinstance(exp, datetime):
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp <= now:
                resp = jsonify(success=False, message="Refresh token expired")
                resp.set_cookie("pm_refresh", "", expires=0, path="/api/auth",
                                httponly=True, secure=True, samesite="None")
                return resp, 401

        if not row.get("is_active"):
            resp = jsonify(success=False, message="Account is disabled")
            resp.set_cookie("pm_refresh", "", expires=0, path="/api/auth",
                            httponly=True, secure=True, samesite="None")
            return resp, 403

        uid = int(row["user_id"])
        has_purchased = check_user_purchased(cur, uid)

        # rotate refresh
        new_raw, new_hash = generate_refresh_token()
        new_expires = now + timedelta(days=REFRESH_EXP_DAYS)

        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        user_agent = (request.headers.get("User-Agent") or "")[:255]

        cur.execute("UPDATE pm_refresh_tokens SET revoked_at = NOW() WHERE id = %s", (row["id"],))
        cur.execute(
            """
            INSERT INTO pm_refresh_tokens
                (user_id, refresh_token_hash, expires_at, ip_address, user_agent, created_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
            """,
            (uid, new_hash, new_expires, ip_address, user_agent)
        )
        conn.commit()

        access_token = create_access_token(uid, row["username"], has_purchased)

        resp = jsonify(
            success=True,
            uid=uid,
            username=row["username"],
            email=row["email"],
            has_purchased=has_purchased,
            access_token=access_token,
            access_expires_in=JWT_EXP_MINUTES * 60,
            refresh_expires_in=REFRESH_EXP_DAYS * 86400,
        )

        resp.set_cookie(
            "pm_refresh",
            new_raw,
            httponly=True,
            secure=True,
            samesite="None",
            max_age=REFRESH_EXP_DAYS * 86400,
            path="/api/auth",
        )

        return resp, 200

    except MySQLError:
        app.logger.exception("[REFRESH] MySQL error")
        return jsonify(success=False, message="Service unavailable"), 503
    except Exception:
        app.logger.exception("[REFRESH] Unhandled error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# ---------- AUTH: LOGOUT (cookie) ----------

@app.route("/api/auth/logout", methods=["POST"])
@jwt_required
def auth_logout():
    raw_refresh = (request.cookies.get("pm_refresh") or "").strip()

    resp = jsonify(success=True, message="Logged out")

    # always clear cookie client-side
    resp.set_cookie("pm_refresh", "", expires=0, path="/api/auth",
                    httponly=True, secure=True, samesite="None")

    if not raw_refresh:
        return resp, 200

    hashed = hashlib.sha256(raw_refresh.encode("utf-8")).hexdigest()

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE pm_refresh_tokens
            SET revoked_at = NOW()
            WHERE refresh_token_hash = %s AND user_id = %s
            """,
            (hashed, g.current_uid)
        )
        conn.commit()
    except Exception:
        app.logger.exception("[LOGOUT] Error (non-fatal)")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return resp, 200

# ---------- USER: ME ----------

@app.route("/api/user/me", methods=["GET"])
@jwt_required
def user_me():
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        
        cur.execute(
            """
            SELECT uid, username, email, is_active, is_verified, created_at
            FROM pm_users
            WHERE uid = %s
            """,
            (g.current_uid,)
        )
        user = cur.fetchone()
        
        if not user:
            return jsonify(success=False, message="User not found"), 404
        
        # Get purchase info
        cur.execute(
            """
            SELECT id, license_key, status, created_at
            FROM pm_purchases
            WHERE user_id = %s AND status = 'completed'
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (g.current_uid,)
        )
        purchase = cur.fetchone()
        
        return jsonify(
            success=True,
            user={
                "uid": user["uid"],
                "username": user["username"],
                "email": user["email"],
                "is_verified": bool(user["is_verified"]),
                "created_at": user["created_at"].isoformat() if user["created_at"] else None,
            },
            purchase={
                "has_purchased": purchase is not None,
                "license_key": purchase["license_key"] if purchase else None,
                "purchased_at": purchase["created_at"].isoformat() if purchase else None,
            } if purchase else {"has_purchased": False}
        ), 200
        
    except Exception:
        app.logger.exception("[USER_ME] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# ---------- Password Manager Entitlements ----------

@app.route("/api/pm/entitlements", methods=["GET"])
@jwt_required
def pm_entitlements():
    """
    Returns Password Manager premium entitlement state for the current user.

    Response:
      {
        "success": true,
        "uid": 123,
        "premium": true,
        "skus": ["premium_lifetime"],
        "expires_at": null
      }
    """
    uid = g.current_uid

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            """
            SELECT sku, expires_at
            FROM pm_entitlements
            WHERE user_id = %s
              AND active = 1
              AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())
            """,
            (uid,),
        )

        rows = cur.fetchall() or []

        skus = []
        expires_list = []

        for r in rows:
            skus.append(r["sku"])
            if r["expires_at"] is not None:
                try:
                    expires_list.append(
                        r["expires_at"].replace(tzinfo=timezone.utc)
                    )
                except Exception:
                    expires_list.append(r["expires_at"])

        premium = len(skus) > 0

        expires_at = None
        if expires_list:
            expires_at = max(expires_list).astimezone(timezone.utc)\
                                          .isoformat()\
                                          .replace("+00:00", "Z")

        return jsonify(
            success=True,
            uid=uid,
            premium=premium,
            skus=skus,
            expires_at=expires_at,
        ), 200

    except MySQLError:
        app.logger.exception("[PM_ENTITLEMENTS] MySQL error")
        return jsonify(success=False, message="Service unavailable"), 503
    except Exception:
        app.logger.exception("[PM_ENTITLEMENTS] Unhandled server error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


# ---------- STRIPE: CREATE CHECKOUT ----------

@app.route("/api/stripe/create-checkout", methods=["POST"])
@jwt_required
def stripe_create_checkout():
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        
        # Check if already purchased
        if check_user_purchased(cur, g.current_uid):
            return jsonify(success=False, message="You already own this product"), 400
        
        # Get user email
        cur.execute("SELECT email FROM pm_users WHERE uid = %s", (g.current_uid,))
        user = cur.fetchone()
        
        if not user:
            return jsonify(success=False, message="User not found"), 404
        
        # Create Stripe Checkout session
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price": STRIPE_PRICE_ID,
                "quantity": 1,
            }],
            mode="payment",
            success_url=f"{FRONTEND_URL}?payment=success",
            cancel_url=f"{FRONTEND_URL}?payment=cancelled",
            customer_email=user["email"],
            metadata={
                "user_id": str(g.current_uid),
                "username": g.current_username,
            },
            allow_promotion_codes=True,
        )
        
        app.logger.info(f"[STRIPE] Checkout created for user {g.current_uid}: {session.id}")
        
        return jsonify(
            success=True,
            checkout_url=session.url,
            session_id=session.id,
        ), 200
        
    except stripe.error.StripeError as e:
        app.logger.exception("[STRIPE] Stripe error")
        return jsonify(success=False, message="Payment service error"), 500
    except Exception:
        app.logger.exception("[STRIPE] Unhandled error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# ---------- STRIPE: WEBHOOK ----------

@app.route("/api/stripe/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature")
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        app.logger.warning("[STRIPE_WEBHOOK] Invalid payload")
        return jsonify(success=False), 400
    except stripe.error.SignatureVerificationError:
        app.logger.warning("[STRIPE_WEBHOOK] Invalid signature")
        return jsonify(success=False), 400
    
    # Handle checkout.session.completed
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        
        user_id = session.get("metadata", {}).get("user_id")
        if not user_id:
            app.logger.warning("[STRIPE_WEBHOOK] No user_id in metadata")
            return jsonify(success=True), 200
        
        user_id = int(user_id)
        payment_id = session.get("payment_intent")
        customer_id = session.get("customer")
        amount = session.get("amount_total", 0)
        
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Check if purchase already exists
            cur.execute(
                "SELECT id FROM pm_purchases WHERE stripe_payment_id = %s",
                (payment_id,)
            )
            if cur.fetchone():
                app.logger.info(f"[STRIPE_WEBHOOK] Purchase already exists for {payment_id}")
                return jsonify(success=True), 200
            
            # Generate license key
            license_key = generate_license_key()
            
            # Insert purchase
            cur.execute(
                """
                INSERT INTO pm_purchases 
                    (user_id, stripe_payment_id, stripe_customer_id, amount_cents, status, license_key, created_at)
                VALUES (%s, %s, %s, %s, 'completed', %s, NOW())
                """,
                (user_id, payment_id, customer_id, amount, license_key)
            )
            conn.commit()
            
            app.logger.info(f"[STRIPE_WEBHOOK] Purchase recorded for user {user_id}, license: {license_key}")
            
        except Exception:
            app.logger.exception("[STRIPE_WEBHOOK] DB error")
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
    return jsonify(success=True), 200

# ---------- DOWNLOAD ----------

@app.route("/api/download", methods=["GET"])
@jwt_required
def download():
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        
        # Check purchase
        cur.execute(
            """
            SELECT id, license_key FROM pm_purchases
            WHERE user_id = %s AND status = 'completed'
            LIMIT 1
            """,
            (g.current_uid,)
        )
        purchase = cur.fetchone()
        
        if not purchase:
            return jsonify(success=False, message="Purchase required"), 403
        
        # Log download
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        user_agent = (request.headers.get("User-Agent") or "")[:255]
        
        cur.execute(
            """
            INSERT INTO pm_download_logs (user_id, purchase_id, ip_address, user_agent, downloaded_at)
            VALUES (%s, %s, %s, %s, NOW())
            """,
            (g.current_uid, purchase["id"], ip_address, user_agent)
        )
        conn.commit()
        
        app.logger.info(f"[DOWNLOAD] User {g.current_uid} downloaded product")
        
        return jsonify(
            success=True,
            download_url=DOWNLOAD_URL,
            license_key=purchase["license_key"],
        ), 200
        
    except Exception:
        app.logger.exception("[DOWNLOAD] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# ---------- Run ----------

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)





