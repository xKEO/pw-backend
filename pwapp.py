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
import base64
from collections import defaultdict
from time import time as unix_time

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

# ---------- Stripe Config (MONTHLY SUBSCRIPTION) ----------
# IMPORTANT:
#   STRIPE_PRICE_ID must be a RECURRING monthly price (not one-time).
STRIPE_SECRET_KEY = _require_env("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = _require_env("STRIPE_WEBHOOK_SECRET")
STRIPE_PRICE_ID = _require_env("STRIPE_PRICE_ID")  # recurring monthly price ID
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://passwordmanager.tech")

stripe.api_key = STRIPE_SECRET_KEY

# ---------- Download Config ----------
DOWNLOAD_URL = os.getenv(
    "DOWNLOAD_URL",
    "https://github.com/yourusername/repo/releases/latest/download/PasswordManager.zip"
)

# ---------- Password Reset Config ----------
PASSWORD_RESET_EXP_HOURS = int(os.getenv("PASSWORD_RESET_EXP_HOURS", "1"))

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
def create_access_token(uid: int, username: str, is_premium: bool) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(uid),
        "username": username,

        # keep the existing field name so your frontend doesn't break:
        # treat "purchased" as "premium active"
        "purchased": bool(is_premium),

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
        g.current_has_purchased = bool(payload.get("purchased", False))  # now means premium
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    """Decorator that requires user to be an admin (is_admin=1)"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT is_admin FROM pm_users WHERE uid = %s", (g.current_uid,))
            row = cur.fetchone()
            if not row or not row.get("is_admin"):
                return jsonify(success=False, message="Admin access required"), 403
            return fn(*args, **kwargs)
        except Exception:
            app.logger.exception("[ADMIN_CHECK] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    return wrapper


def log_admin_action(cur, admin_uid: int, action: str, target_user_id: int | None = None, details: str | None = None):
    """Log admin action to audit table"""
    cur.execute(
        """
        INSERT INTO pm_admin_audit (admin_uid, action, target_user_id, details, created_at)
        VALUES (%s, %s, %s, %s, NOW())
        """,
        (admin_uid, action, target_user_id, details)
    )


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

def _as_utc(dt: datetime) -> datetime:
    if not isinstance(dt, datetime):
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

# ----- ENTITLEMENTS (subscription truth) -----
# Assumes pm_entitlements columns: user_id, sku, active, expires_at
# - active: 1/0
# - expires_at: nullable datetime (or future datetime)
PREMIUM_SKU = os.getenv("PREMIUM_SKU", "premium_monthly")

def check_user_premium(cur, uid: int) -> bool:
    cur.execute(
        """
        SELECT 1
        FROM pm_entitlements
        WHERE user_id = %s
          AND active = 1
          AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())
        LIMIT 1
        """,
        (uid,)
    )
    return cur.fetchone() is not None

def upsert_premium_entitlement(cur, uid: int, expires_at_utc: datetime | None):
    """
    Creates or updates the premium entitlement row.
    If expires_at_utc is provided, store it; if None, store NULL (not recommended for subscriptions).
    """
    expires_sql = None
    if expires_at_utc is not None:
        expires_at_utc = _as_utc(expires_at_utc)
        # MySQL connector can bind datetime directly
        expires_sql = expires_at_utc

    # If you have a UNIQUE(user_id, sku) this is perfect.
    # If not, this will still usually work if you only ever create one row.
    cur.execute(
        """
        INSERT INTO pm_entitlements (user_id, sku, active, expires_at)
        VALUES (%s, %s, 1, %s)
        ON DUPLICATE KEY UPDATE
          active = 1,
          expires_at = VALUES(expires_at)
        """,
        (uid, PREMIUM_SKU, expires_sql)
    )

def deactivate_premium_entitlement(cur, uid: int):
    cur.execute(
        """
        UPDATE pm_entitlements
        SET active = 0
        WHERE user_id = %s AND sku = %s
        """,
        (uid, PREMIUM_SKU)
    )

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
        is_premium = check_user_premium(cur, uid)

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

        access_token = create_access_token(uid, user["username"], is_premium)

        resp = jsonify(
            success=True,
            uid=uid,
            username=user["username"],
            email=user["email"],
            has_purchased=is_premium,  # keep field name, now means premium
            access_token=access_token,
            access_expires_in=JWT_EXP_MINUTES * 60,
            refresh_expires_in=REFRESH_EXP_DAYS * 86400,
        )

        resp.set_cookie(
            "pm_refresh",
            raw_refresh,
            httponly=True,
            secure=True,
            samesite="None",
            max_age=REFRESH_EXP_DAYS * 86400,
            path="/api/auth",
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

        cur.execute("SELECT uid FROM pm_users WHERE username = %s LIMIT 1", (username,))
        if cur.fetchone():
            return jsonify(success=False, message="Username already taken"), 409

        cur.execute("SELECT uid FROM pm_users WHERE email = %s LIMIT 1", (email,))
        if cur.fetchone():
            return jsonify(success=False, message="Email already registered"), 409

        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

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

        def _clear_cookie_and(status_code: int, msg: str):
            resp = jsonify(success=False, message=msg)
            resp.set_cookie("pm_refresh", "", expires=0, path="/api/auth",
                            httponly=True, secure=True, samesite="None")
            return resp, status_code

        if not row:
            return _clear_cookie_and(401, "Invalid refresh token")

        if row["revoked_at"] is not None:
            return _clear_cookie_and(401, "Refresh token revoked")

        now = datetime.now(timezone.utc)
        exp = row["expires_at"]
        if isinstance(exp, datetime):
            exp = _as_utc(exp)
            if exp <= now:
                return _clear_cookie_and(401, "Refresh token expired")

        if not row.get("is_active"):
            return _clear_cookie_and(403, "Account is disabled")

        uid = int(row["user_id"])
        is_premium = check_user_premium(cur, uid)

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

        access_token = create_access_token(uid, row["username"], is_premium)

        resp = jsonify(
            success=True,
            uid=uid,
            username=row["username"],
            email=row["email"],
            has_purchased=is_premium,  # now means premium
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

# ---------- SESSION MANAGEMENT ----------
@app.route("/api/auth/sessions", methods=["GET"])
@jwt_required
def auth_sessions_list():
    """List user's active sessions (refresh tokens)"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            """
            SELECT id, ip_address, user_agent, created_at, expires_at
            FROM pm_refresh_tokens
            WHERE user_id = %s AND revoked_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC
            LIMIT 20
            """,
            (g.current_uid,)
        )
        sessions = cur.fetchall() or []

        for s in sessions:
            if s.get("created_at"):
                s["created_at"] = _as_utc(s["created_at"]).isoformat().replace("+00:00", "Z")
            if s.get("expires_at"):
                s["expires_at"] = _as_utc(s["expires_at"]).isoformat().replace("+00:00", "Z")

        return jsonify(success=True, sessions=sessions), 200

    except Exception:
        app.logger.exception("[SESSIONS_LIST] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/auth/sessions/<int:session_id>", methods=["DELETE"])
@jwt_required
def auth_sessions_revoke(session_id: int):
    """Revoke a specific session"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            """
            UPDATE pm_refresh_tokens
            SET revoked_at = NOW()
            WHERE id = %s AND user_id = %s AND revoked_at IS NULL
            """,
            (session_id, g.current_uid)
        )
        revoked = cur.rowcount
        conn.commit()

        if revoked == 0:
            return jsonify(success=False, message="Session not found"), 404

        app.logger.info(f"[SESSION_REVOKE] User {g.current_uid} revoked session {session_id}")
        return jsonify(success=True, message="Session revoked"), 200

    except Exception:
        app.logger.exception("[SESSION_REVOKE] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/auth/sessions/revoke-all", methods=["POST"])
@jwt_required
def auth_sessions_revoke_all():
    """Revoke all sessions except current"""
    raw_refresh = (request.cookies.get("pm_refresh") or "").strip()
    current_hash = hashlib.sha256(raw_refresh.encode("utf-8")).hexdigest() if raw_refresh else None

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        if current_hash:
            cur.execute(
                """
                UPDATE pm_refresh_tokens
                SET revoked_at = NOW()
                WHERE user_id = %s AND revoked_at IS NULL AND refresh_token_hash != %s
                """,
                (g.current_uid, current_hash)
            )
        else:
            cur.execute(
                """
                UPDATE pm_refresh_tokens
                SET revoked_at = NOW()
                WHERE user_id = %s AND revoked_at IS NULL
                """,
                (g.current_uid,)
            )

        revoked = cur.rowcount
        conn.commit()

        app.logger.info(f"[SESSION_REVOKE_ALL] User {g.current_uid} revoked {revoked} sessions")
        return jsonify(success=True, message=f"Revoked {revoked} sessions"), 200

    except Exception:
        app.logger.exception("[SESSION_REVOKE_ALL] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# ---------- PASSWORD RESET ----------
@app.route("/api/auth/forgot-password", methods=["POST"])
def auth_forgot_password():
    """Request password reset email"""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return jsonify(success=False, message="Email is required"), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute("SELECT uid, username, is_active FROM pm_users WHERE email = %s LIMIT 1", (email,))
        user = cur.fetchone()

        # Always return success to prevent email enumeration
        if not user or not user.get("is_active"):
            app.logger.info(f"[FORGOT_PASSWORD] Request for unknown/inactive email")
            return jsonify(success=True, message="If that email exists, a reset link has been sent"), 200

        # Generate reset token
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=PASSWORD_RESET_EXP_HOURS)

        # Invalidate old tokens
        cur.execute(
            "UPDATE pm_password_resets SET used_at = NOW() WHERE user_id = %s AND used_at IS NULL",
            (user["uid"],)
        )

        # Create new token
        cur.execute(
            """
            INSERT INTO pm_password_resets (user_id, token_hash, expires_at, created_at)
            VALUES (%s, %s, %s, NOW())
            """,
            (user["uid"], token_hash, expires_at)
        )
        conn.commit()

        # TODO: Send email with reset link
        # reset_url = f"{FRONTEND_URL}/reset-password?token={raw_token}"
        # send_email(email, "Password Reset", f"Reset your password: {reset_url}")

        app.logger.info(f"[FORGOT_PASSWORD] Reset token created for user {user['uid']}")

        # For development, return token (REMOVE IN PRODUCTION)
        return jsonify(
            success=True,
            message="If that email exists, a reset link has been sent",
            # debug_token=raw_token,  # REMOVE IN PRODUCTION
        ), 200

    except Exception:
        app.logger.exception("[FORGOT_PASSWORD] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/auth/reset-password", methods=["POST"])
def auth_reset_password():
    """Complete password reset with token"""
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    new_password = data.get("password") or ""
    new_password2 = data.get("password2") or ""

    if not token:
        return jsonify(success=False, message="Reset token is required"), 400

    valid, msg = validate_password(new_password)
    if not valid:
        return jsonify(success=False, message=msg), 400

    if new_password != new_password2:
        return jsonify(success=False, message="Passwords do not match"), 400

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            """
            SELECT r.id, r.user_id, r.expires_at, r.used_at, u.is_active
            FROM pm_password_resets r
            JOIN pm_users u ON u.uid = r.user_id
            WHERE r.token_hash = %s
            LIMIT 1
            """,
            (token_hash,)
        )
        reset = cur.fetchone()

        if not reset:
            return jsonify(success=False, message="Invalid or expired reset token"), 400

        if reset.get("used_at"):
            return jsonify(success=False, message="Reset token already used"), 400

        expires = _as_utc(reset["expires_at"])
        if expires <= datetime.now(timezone.utc):
            return jsonify(success=False, message="Reset token expired"), 400

        if not reset.get("is_active"):
            return jsonify(success=False, message="Account is disabled"), 403

        # Update password
        password_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        cur.execute("UPDATE pm_users SET password = %s WHERE uid = %s", (password_hash, reset["user_id"]))

        # Mark token as used
        cur.execute("UPDATE pm_password_resets SET used_at = NOW() WHERE id = %s", (reset["id"],))

        # Revoke all refresh tokens (force re-login)
        cur.execute(
            "UPDATE pm_refresh_tokens SET revoked_at = NOW() WHERE user_id = %s AND revoked_at IS NULL",
            (reset["user_id"],)
        )

        conn.commit()

        app.logger.info(f"[RESET_PASSWORD] User {reset['user_id']} reset their password")
        return jsonify(success=True, message="Password reset successfully"), 200

    except Exception:
        app.logger.exception("[RESET_PASSWORD] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

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

        premium = check_user_premium(cur, g.current_uid)

        # Keep "purchase" block for backwards compatibility, but it may be false now.
        # (If you want: you can remove later.)
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
            } if purchase else {"has_purchased": False},
            premium={
                "active": bool(premium),
            }
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
        "skus": ["premium_monthly"],
        "expires_at": "2026-01-25T00:00:00Z"
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
                    expires_list.append(_as_utc(r["expires_at"]))
                except Exception:
                    pass

        premium = len(skus) > 0

        expires_at = None
        if expires_list:
            expires_at = max(expires_list).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

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

# ---------- STRIPE: CREATE CHECKOUT (MONTHLY SUBSCRIPTION) ----------
@app.route("/api/stripe/create-checkout", methods=["POST"])
@jwt_required
def stripe_create_checkout():
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        # If already premium, don't start checkout again (until you add portal).
        if check_user_premium(cur, g.current_uid):
            return jsonify(success=False, message="Premium is already active"), 400

        # Get user email
        cur.execute("SELECT email FROM pm_users WHERE uid = %s", (g.current_uid,))
        user = cur.fetchone()
        if not user:
            return jsonify(success=False, message="User not found"), 404

        # Create Stripe Checkout session (SUBSCRIPTION)
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            mode="subscription",
            success_url=f"{FRONTEND_URL}?payment=success",
            cancel_url=f"{FRONTEND_URL}?payment=cancelled",
            customer_email=user["email"],
            metadata={
                "user_id": str(g.current_uid),
                "username": g.current_username,
                "sku": PREMIUM_SKU,
            },
            allow_promotion_codes=True,
        )

        app.logger.info(f"[STRIPE] Subscription checkout created for user {g.current_uid}: {session.id}")
        return jsonify(success=True, checkout_url=session.url, session_id=session.id), 200

    except stripe.error.StripeError:
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

# ---------- Helper: Get user_id from subscription ----------
def get_user_id_from_subscription(cur, subscription_id: str) -> int | None:
    """Look up user_id from pm_stripe_subscriptions table"""
    cur.execute(
        """
        SELECT user_id FROM pm_stripe_subscriptions
        WHERE stripe_subscription_id = %s
        LIMIT 1
        """,
        (subscription_id,)
    )
    row = cur.fetchone()
    return int(row["user_id"]) if row else None

# ---------- STRIPE: WEBHOOK (SUBSCRIPTION LIFECYCLE → pm_entitlements) ----------
@app.route("/api/stripe/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        app.logger.warning("[STRIPE_WEBHOOK] Invalid payload")
        return jsonify(success=False), 400
    except stripe.error.SignatureVerificationError:
        app.logger.warning("[STRIPE_WEBHOOK] Invalid signature")
        return jsonify(success=False), 400

    etype = event.get("type")
    obj = event.get("data", {}).get("object", {})

    # 1) Checkout completed (subscription started)
    if etype == "checkout.session.completed":
        # For subscription checkout, session has 'subscription'
        meta = obj.get("metadata", {}) or {}
        user_id = meta.get("user_id")
        sku = meta.get("sku") or PREMIUM_SKU
        subscription_id = obj.get("subscription")
        customer_id = obj.get("customer")

        if user_id and subscription_id:
            conn = None
            cur = None
            try:
                user_id = int(user_id)

                # Retrieve subscription to get current_period_end
                sub = stripe.Subscription.retrieve(subscription_id)
                cpe = sub.get("current_period_end")
                expires_at = None
                if cpe:
                    expires_at = datetime.fromtimestamp(int(cpe), tz=timezone.utc)

                conn = get_db_connection()
                cur = conn.cursor(dictionary=True)

                # Activate entitlement
                upsert_premium_entitlement(cur, user_id, expires_at)

                # Track subscription in our database
                cur.execute(
                    """
                    INSERT INTO pm_stripe_subscriptions (user_id, stripe_subscription_id, stripe_customer_id, status, created_at)
                    VALUES (%s, %s, %s, 'active', NOW())
                    ON DUPLICATE KEY UPDATE
                      user_id = VALUES(user_id),
                      stripe_customer_id = VALUES(stripe_customer_id),
                      status = 'active',
                      updated_at = NOW()
                    """,
                    (user_id, subscription_id, customer_id)
                )

                conn.commit()
                app.logger.info(f"[ENTITLEMENT] Activated {sku} for user {user_id}, expires_at={expires_at}")
            except Exception:
                app.logger.exception("[STRIPE_WEBHOOK] Failed handling checkout.session.completed")
            finally:
                if cur:
                    cur.close()
                if conn:
                    conn.close()
        return jsonify(success=True), 200

    # 2) Subscription updated (renewals, plan changes, payment issues, etc.)
    #    We use this to keep expires_at aligned with Stripe current_period_end.
    if etype == "customer.subscription.updated":
        subscription_id = obj.get("id")
        status = obj.get("status")  # 'active', 'past_due', 'canceled', 'unpaid', etc.

        if not subscription_id:
            return jsonify(success=True), 200

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)

            user_id = get_user_id_from_subscription(cur, subscription_id)
            if not user_id:
                app.logger.warning(f"[STRIPE_WEBHOOK] No user found for subscription {subscription_id}")
                return jsonify(success=True), 200

            # Update subscription status in our table
            cur.execute(
                """
                UPDATE pm_stripe_subscriptions
                SET status = %s, updated_at = NOW()
                WHERE stripe_subscription_id = %s
                """,
                (status, subscription_id)
            )

            if status in ("active", "trialing"):
                # Refresh entitlement with new period end
                sub = stripe.Subscription.retrieve(subscription_id)
                cpe = sub.get("current_period_end")
                expires_at = datetime.fromtimestamp(int(cpe), tz=timezone.utc) if cpe else None
                upsert_premium_entitlement(cur, user_id, expires_at)
                app.logger.info(f"[ENTITLEMENT] Renewed for user {user_id}, expires_at={expires_at}")
            else:
                # Past due / unpaid / paused -> deactivate
                deactivate_premium_entitlement(cur, user_id)
                app.logger.info(f"[ENTITLEMENT] Deactivated for user {user_id} (status={status})")

            conn.commit()
        except Exception:
            app.logger.exception("[STRIPE_WEBHOOK] Error handling subscription.updated")
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

        return jsonify(success=True), 200

    # 3) Subscription deleted (canceled or ended)
    if etype == "customer.subscription.deleted":
        subscription_id = obj.get("id")

        if not subscription_id:
            return jsonify(success=True), 200

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)

            user_id = get_user_id_from_subscription(cur, subscription_id)
            if user_id:
                deactivate_premium_entitlement(cur, user_id)
                cur.execute(
                    """
                    UPDATE pm_stripe_subscriptions
                    SET status = 'canceled', updated_at = NOW()
                    WHERE stripe_subscription_id = %s
                    """,
                    (subscription_id,)
                )
                conn.commit()
                app.logger.info(f"[ENTITLEMENT] Subscription deleted for user {user_id}")
        except Exception:
            app.logger.exception("[STRIPE_WEBHOOK] Error handling subscription.deleted")
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

        return jsonify(success=True), 200

    # (Optional) Invoice payment failed -> deactivate or grace period
    # if etype == "invoice.payment_failed": ...

    return jsonify(success=True), 200

# ---------- STRIPE BILLING PORTAL ----------
@app.route("/api/stripe/create-portal-session", methods=["POST"])
@jwt_required
def stripe_create_portal_session():
    """Create Stripe Customer Portal session for subscription management"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        # Get user's Stripe customer ID from subscription
        cur.execute(
            """
            SELECT stripe_customer_id FROM pm_stripe_subscriptions
            WHERE user_id = %s AND stripe_customer_id IS NOT NULL
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (g.current_uid,)
        )
        row = cur.fetchone()

        if not row or not row.get("stripe_customer_id"):
            return jsonify(success=False, message="No billing account found"), 404

        session = stripe.billing_portal.Session.create(
            customer=row["stripe_customer_id"],
            return_url=f"{FRONTEND_URL}/settings/billing",
        )

        app.logger.info(f"[STRIPE_PORTAL] User {g.current_uid} opened billing portal")
        return jsonify(success=True, portal_url=session.url), 200

    except stripe.error.StripeError:
        app.logger.exception("[STRIPE_PORTAL] Stripe error")
        return jsonify(success=False, message="Billing service error"), 500
    except Exception:
        app.logger.exception("[STRIPE_PORTAL] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# ---------- DOWNLOAD (NOW ENFORCES SUBSCRIPTION ENTITLEMENT) ----------
@app.route("/api/download", methods=["GET"])
@jwt_required
def download():
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        # Check premium entitlement (monthly subscription plan)
        if not check_user_premium(cur, g.current_uid):
            return jsonify(success=False, message="Premium subscription required"), 403

        # Log download (keep existing table)
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        user_agent = (request.headers.get("User-Agent") or "")[:255]

        # If pm_download_logs expects purchase_id, you have two options:
        #  1) Alter schema to allow NULL purchase_id
        #  2) Create a separate subscription_download_logs table
        #
        # Here we attempt to insert with NULL purchase_id; if your schema forbids it,
        # you'll see an exception in logs and the download will still succeed.
        try:
            cur.execute(
                """
                INSERT INTO pm_download_logs (user_id, purchase_id, ip_address, user_agent, downloaded_at)
                VALUES (%s, NULL, %s, %s, NOW())
                """,
                (g.current_uid, ip_address, user_agent)
            )
            conn.commit()
        except Exception:
            app.logger.exception("[DOWNLOAD] Could not write download log (non-fatal)")

        app.logger.info(f"[DOWNLOAD] User {g.current_uid} downloaded product (premium)")

        return jsonify(
            success=True,
            download_url=DOWNLOAD_URL,
            license_key=None,  # subscription flow: no perma license required (optional)
        ), 200

    except Exception:
        app.logger.exception("[DOWNLOAD] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


# ============================================================
# ADMIN ENDPOINTS
# ============================================================

@app.route("/api/admin/users", methods=["GET"])
@jwt_required
@admin_required
def admin_user_search():
    """Search users by email, username, or uid"""
    query = (request.args.get("query") or "").strip()
    limit = min(int(request.args.get("limit", 50)), 100)
    offset = int(request.args.get("offset", 0))

    if not query:
        return jsonify(success=False, message="query parameter required"), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        if query.isdigit():
            cur.execute(
                """
                SELECT uid, username, email, is_active, is_verified, is_admin, created_at
                FROM pm_users WHERE uid = %s LIMIT 1
                """,
                (int(query),)
            )
        else:
            search_pattern = f"%{query}%"
            cur.execute(
                """
                SELECT uid, username, email, is_active, is_verified, is_admin, created_at
                FROM pm_users WHERE username LIKE %s OR email LIKE %s
                ORDER BY created_at DESC LIMIT %s OFFSET %s
                """,
                (search_pattern, search_pattern, limit, offset)
            )

        users = cur.fetchall() or []
        for u in users:
            if u.get("created_at"):
                u["created_at"] = _as_utc(u["created_at"]).isoformat().replace("+00:00", "Z")
            u["is_active"] = bool(u.get("is_active"))
            u["is_verified"] = bool(u.get("is_verified"))
            u["is_admin"] = bool(u.get("is_admin"))

        return jsonify(success=True, users=users, count=len(users)), 200
    except Exception:
        app.logger.exception("[ADMIN_USER_SEARCH] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/admin/users/<int:uid>", methods=["GET"])
@jwt_required
@admin_required
def admin_user_detail(uid: int):
    """Get full user detail with premium, usage, vault count, sessions"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            "SELECT uid, username, email, is_active, is_verified, is_admin, created_at FROM pm_users WHERE uid = %s",
            (uid,)
        )
        user = cur.fetchone()
        if not user:
            return jsonify(success=False, message="User not found"), 404

        if user.get("created_at"):
            user["created_at"] = _as_utc(user["created_at"]).isoformat().replace("+00:00", "Z")
        user["is_active"] = bool(user.get("is_active"))
        user["is_verified"] = bool(user.get("is_verified"))
        user["is_admin"] = bool(user.get("is_admin"))

        cur.execute(
            "SELECT sku, active, expires_at, created_at FROM pm_entitlements WHERE user_id = %s ORDER BY created_at DESC",
            (uid,)
        )
        entitlements = cur.fetchall() or []
        for e in entitlements:
            e["active"] = bool(e.get("active"))
            if e.get("expires_at"):
                e["expires_at"] = _as_utc(e["expires_at"]).isoformat().replace("+00:00", "Z")
            if e.get("created_at"):
                e["created_at"] = _as_utc(e["created_at"]).isoformat().replace("+00:00", "Z")

        is_premium = check_user_premium(cur, uid)

        cur.execute(
            "SELECT COUNT(*) AS vault_count, COALESCE(SUM(LENGTH(vault_data)), 0) AS total_bytes FROM pm_vaults WHERE user_id = %s AND deleted_at IS NULL",
            (uid,)
        )
        usage = cur.fetchone() or {"vault_count": 0, "total_bytes": 0}

        cur.execute(
            "SELECT COUNT(*) AS session_count FROM pm_refresh_tokens WHERE user_id = %s AND revoked_at IS NULL AND expires_at > NOW()",
            (uid,)
        )
        sessions = cur.fetchone() or {"session_count": 0}

        cur.execute(
            "SELECT stripe_subscription_id, stripe_customer_id, status, created_at FROM pm_stripe_subscriptions WHERE user_id = %s ORDER BY created_at DESC LIMIT 1",
            (uid,)
        )
        stripe_sub = cur.fetchone()
        if stripe_sub and stripe_sub.get("created_at"):
            stripe_sub["created_at"] = _as_utc(stripe_sub["created_at"]).isoformat().replace("+00:00", "Z")

        cur.execute(
            """
            SELECT n.id, n.note, n.created_at, u.username AS admin_username
            FROM pm_admin_notes n JOIN pm_users u ON u.uid = n.admin_uid
            WHERE n.user_id = %s ORDER BY n.created_at DESC LIMIT 10
            """,
            (uid,)
        )
        notes = cur.fetchall() or []
        for n in notes:
            if n.get("created_at"):
                n["created_at"] = _as_utc(n["created_at"]).isoformat().replace("+00:00", "Z")

        return jsonify(
            success=True,
            user=user,
            premium={"active": is_premium, "entitlements": entitlements},
            usage={"vault_count": usage["vault_count"], "total_bytes": int(usage["total_bytes"])},
            sessions={"active_count": sessions["session_count"]},
            stripe=stripe_sub,
            notes=notes,
        ), 200
    except Exception:
        app.logger.exception("[ADMIN_USER_DETAIL] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/admin/users/<int:uid>/disable", methods=["POST"])
@jwt_required
@admin_required
def admin_user_disable(uid: int):
    """Disable user account"""
    if uid == g.current_uid:
        return jsonify(success=False, message="Cannot disable your own account"), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("UPDATE pm_users SET is_active = 0 WHERE uid = %s", (uid,))
        if cur.rowcount == 0:
            return jsonify(success=False, message="User not found"), 404

        cur.execute("UPDATE pm_refresh_tokens SET revoked_at = NOW() WHERE user_id = %s AND revoked_at IS NULL", (uid,))
        log_admin_action(cur, g.current_uid, "user_disable", uid)
        conn.commit()

        app.logger.info(f"[ADMIN] User {g.current_uid} disabled user {uid}")
        return jsonify(success=True, message="User disabled"), 200
    except Exception:
        app.logger.exception("[ADMIN_USER_DISABLE] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/admin/users/<int:uid>/enable", methods=["POST"])
@jwt_required
@admin_required
def admin_user_enable(uid: int):
    """Enable user account"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("UPDATE pm_users SET is_active = 1 WHERE uid = %s", (uid,))
        if cur.rowcount == 0:
            return jsonify(success=False, message="User not found"), 404

        log_admin_action(cur, g.current_uid, "user_enable", uid)
        conn.commit()

        app.logger.info(f"[ADMIN] User {g.current_uid} enabled user {uid}")
        return jsonify(success=True, message="User enabled"), 200
    except Exception:
        app.logger.exception("[ADMIN_USER_ENABLE] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/admin/users/<int:uid>/set-admin", methods=["POST"])
@jwt_required
@admin_required
def admin_user_set_admin(uid: int):
    """Grant or revoke admin status"""
    data = request.get_json(silent=True) or {}
    is_admin = bool(data.get("is_admin", False))

    if uid == g.current_uid and not is_admin:
        return jsonify(success=False, message="Cannot remove your own admin status"), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("UPDATE pm_users SET is_admin = %s WHERE uid = %s", (1 if is_admin else 0, uid))
        if cur.rowcount == 0:
            return jsonify(success=False, message="User not found"), 404

        action = "admin_grant" if is_admin else "admin_revoke"
        log_admin_action(cur, g.current_uid, action, uid)
        conn.commit()

        app.logger.info(f"[ADMIN] User {g.current_uid} set is_admin={is_admin} for user {uid}")
        return jsonify(success=True, message=f"Admin status {'granted' if is_admin else 'revoked'}"), 200
    except Exception:
        app.logger.exception("[ADMIN_SET_ADMIN] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


# ---------- ADMIN: SESSION MANAGEMENT ----------

@app.route("/api/admin/users/<int:uid>/sessions", methods=["GET"])
@jwt_required
@admin_required
def admin_user_sessions(uid: int):
    """List user's active sessions"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            """
            SELECT id, ip_address, user_agent, created_at, expires_at
            FROM pm_refresh_tokens
            WHERE user_id = %s AND revoked_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC
            """,
            (uid,)
        )
        sessions = cur.fetchall() or []

        for s in sessions:
            if s.get("created_at"):
                s["created_at"] = _as_utc(s["created_at"]).isoformat().replace("+00:00", "Z")
            if s.get("expires_at"):
                s["expires_at"] = _as_utc(s["expires_at"]).isoformat().replace("+00:00", "Z")

        return jsonify(success=True, sessions=sessions), 200
    except Exception:
        app.logger.exception("[ADMIN_USER_SESSIONS] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/admin/users/<int:uid>/sessions/revoke-all", methods=["POST"])
@jwt_required
@admin_required
def admin_user_sessions_revoke_all(uid: int):
    """Revoke all user sessions"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            "UPDATE pm_refresh_tokens SET revoked_at = NOW() WHERE user_id = %s AND revoked_at IS NULL",
            (uid,)
        )
        revoked = cur.rowcount

        log_admin_action(cur, g.current_uid, "sessions_revoke_all", uid, f"Revoked {revoked} sessions")
        conn.commit()

        app.logger.info(f"[ADMIN] User {g.current_uid} revoked all sessions for user {uid}")
        return jsonify(success=True, message=f"Revoked {revoked} sessions"), 200
    except Exception:
        app.logger.exception("[ADMIN_SESSIONS_REVOKE_ALL] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/admin/sessions/<int:session_id>/revoke", methods=["POST"])
@jwt_required
@admin_required
def admin_session_revoke(session_id: int):
    """Revoke specific session"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute("SELECT user_id FROM pm_refresh_tokens WHERE id = %s", (session_id,))
        session = cur.fetchone()
        if not session:
            return jsonify(success=False, message="Session not found"), 404

        cur.execute(
            "UPDATE pm_refresh_tokens SET revoked_at = NOW() WHERE id = %s AND revoked_at IS NULL",
            (session_id,)
        )

        log_admin_action(cur, g.current_uid, "session_revoke", session["user_id"], f"Session {session_id}")
        conn.commit()

        app.logger.info(f"[ADMIN] User {g.current_uid} revoked session {session_id}")
        return jsonify(success=True, message="Session revoked"), 200
    except Exception:
        app.logger.exception("[ADMIN_SESSION_REVOKE] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


# ---------- ADMIN: ENTITLEMENT MANAGEMENT ----------

@app.route("/api/admin/users/<int:uid>/entitlements", methods=["GET"])
@jwt_required
@admin_required
def admin_user_entitlements(uid: int):
    """Get user's entitlements"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            """
            SELECT id, sku, active, expires_at, created_at
            FROM pm_entitlements
            WHERE user_id = %s
            ORDER BY created_at DESC
            """,
            (uid,)
        )
        entitlements = cur.fetchall() or []

        for e in entitlements:
            e["active"] = bool(e.get("active"))
            if e.get("expires_at"):
                e["expires_at"] = _as_utc(e["expires_at"]).isoformat().replace("+00:00", "Z")
            if e.get("created_at"):
                e["created_at"] = _as_utc(e["created_at"]).isoformat().replace("+00:00", "Z")

        return jsonify(success=True, entitlements=entitlements), 200
    except Exception:
        app.logger.exception("[ADMIN_USER_ENTITLEMENTS] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/admin/users/<int:uid>/entitlements/grant", methods=["POST"])
@jwt_required
@admin_required
def admin_entitlement_grant(uid: int):
    """Grant entitlement to user"""
    data = request.get_json(silent=True) or {}
    sku = (data.get("sku") or PREMIUM_SKU).strip()
    days = data.get("days")
    expires_at_str = data.get("expires_at")

    if expires_at_str:
        try:
            expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
            expires_at = _as_utc(expires_at)
        except Exception:
            return jsonify(success=False, message="Invalid expires_at format"), 400
    elif days:
        try:
            expires_at = datetime.now(timezone.utc) + timedelta(days=int(days))
        except Exception:
            return jsonify(success=False, message="Invalid days value"), 400
    else:
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT uid FROM pm_users WHERE uid = %s", (uid,))
        if not cur.fetchone():
            return jsonify(success=False, message="User not found"), 404

        cur.execute(
            """
            INSERT INTO pm_entitlements (user_id, sku, active, expires_at)
            VALUES (%s, %s, 1, %s)
            ON DUPLICATE KEY UPDATE active = 1, expires_at = VALUES(expires_at)
            """,
            (uid, sku, expires_at)
        )

        log_admin_action(cur, g.current_uid, "entitlement_grant", uid, f"SKU: {sku}, expires: {expires_at.isoformat()}")
        conn.commit()

        app.logger.info(f"[ADMIN] User {g.current_uid} granted {sku} to user {uid} until {expires_at}")
        return jsonify(
            success=True,
            message="Entitlement granted",
            expires_at=expires_at.isoformat().replace("+00:00", "Z")
        ), 200
    except Exception:
        app.logger.exception("[ADMIN_ENTITLEMENT_GRANT] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/admin/users/<int:uid>/entitlements/revoke", methods=["POST"])
@jwt_required
@admin_required
def admin_entitlement_revoke(uid: int):
    """Revoke entitlement from user"""
    data = request.get_json(silent=True) or {}
    sku = (data.get("sku") or PREMIUM_SKU).strip()

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            "UPDATE pm_entitlements SET active = 0 WHERE user_id = %s AND sku = %s",
            (uid, sku)
        )

        log_admin_action(cur, g.current_uid, "entitlement_revoke", uid, f"SKU: {sku}")
        conn.commit()

        app.logger.info(f"[ADMIN] User {g.current_uid} revoked {sku} from user {uid}")
        return jsonify(success=True, message="Entitlement revoked"), 200
    except Exception:
        app.logger.exception("[ADMIN_ENTITLEMENT_REVOKE] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


# ---------- ADMIN: VAULT & STORAGE ----------

@app.route("/api/admin/users/<int:uid>/usage", methods=["GET"])
@jwt_required
@admin_required
def admin_user_usage(uid: int):
    """Get user's storage usage"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            """
            SELECT
                COUNT(*) AS vault_count,
                COALESCE(SUM(LENGTH(vault_data)), 0) AS total_bytes,
                COALESCE(SUM(current_version), 0) AS total_versions
            FROM pm_vaults
            WHERE user_id = %s AND deleted_at IS NULL
            """,
            (uid,)
        )
        vaults = cur.fetchone() or {"vault_count": 0, "total_bytes": 0, "total_versions": 0}

        cur.execute(
            "SELECT COUNT(*) AS shared_count FROM pm_shared_items WHERE owner_id = %s",
            (uid,)
        )
        shared = cur.fetchone() or {"shared_count": 0}

        cur.execute(
            "SELECT COUNT(*) AS download_count FROM pm_download_logs WHERE user_id = %s",
            (uid,)
        )
        downloads = cur.fetchone() or {"download_count": 0}

        return jsonify(
            success=True,
            usage={
                "vault_count": vaults["vault_count"],
                "total_bytes": int(vaults["total_bytes"]),
                "total_versions": int(vaults["total_versions"]),
                "shared_items": shared["shared_count"],
                "downloads": downloads["download_count"],
            }
        ), 200
    except Exception:
        app.logger.exception("[ADMIN_USER_USAGE] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/admin/users/<int:uid>/vaults", methods=["GET"])
@jwt_required
@admin_required
def admin_user_vaults(uid: int):
    """List user's vaults (metadata only)"""
    include_deleted = request.args.get("include_deleted", "false").lower() == "true"

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        if include_deleted:
            cur.execute(
                """
                SELECT id, vault_slug, vault_name, current_version,
                       LENGTH(vault_data) AS size_bytes, created_at, updated_at, deleted_at
                FROM pm_vaults
                WHERE user_id = %s
                ORDER BY created_at DESC
                """,
                (uid,)
            )
        else:
            cur.execute(
                """
                SELECT id, vault_slug, vault_name, current_version,
                       LENGTH(vault_data) AS size_bytes, created_at, updated_at
                FROM pm_vaults
                WHERE user_id = %s AND deleted_at IS NULL
                ORDER BY created_at DESC
                """,
                (uid,)
            )

        vaults = cur.fetchall() or []

        for v in vaults:
            if v.get("created_at"):
                v["created_at"] = _as_utc(v["created_at"]).isoformat().replace("+00:00", "Z")
            if v.get("updated_at"):
                v["updated_at"] = _as_utc(v["updated_at"]).isoformat().replace("+00:00", "Z")
            if v.get("deleted_at"):
                v["deleted_at"] = _as_utc(v["deleted_at"]).isoformat().replace("+00:00", "Z")

        return jsonify(success=True, vaults=vaults), 200
    except Exception:
        app.logger.exception("[ADMIN_USER_VAULTS] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/admin/vaults/<int:vault_id>/soft-delete", methods=["POST"])
@jwt_required
@admin_required
def admin_vault_soft_delete(vault_id: int):
    """Soft delete a vault"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute("SELECT user_id, vault_slug FROM pm_vaults WHERE id = %s", (vault_id,))
        vault = cur.fetchone()
        if not vault:
            return jsonify(success=False, message="Vault not found"), 404

        cur.execute("UPDATE pm_vaults SET deleted_at = NOW() WHERE id = %s", (vault_id,))

        log_admin_action(cur, g.current_uid, "vault_soft_delete", vault["user_id"], f"Vault: {vault['vault_slug']}")
        conn.commit()

        app.logger.info(f"[ADMIN] User {g.current_uid} soft-deleted vault {vault_id}")
        return jsonify(success=True, message="Vault soft-deleted"), 200
    except Exception:
        app.logger.exception("[ADMIN_VAULT_SOFT_DELETE] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/admin/vaults/<int:vault_id>/restore", methods=["POST"])
@jwt_required
@admin_required
def admin_vault_restore(vault_id: int):
    """Restore a soft-deleted vault"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute("SELECT user_id, vault_slug FROM pm_vaults WHERE id = %s", (vault_id,))
        vault = cur.fetchone()
        if not vault:
            return jsonify(success=False, message="Vault not found"), 404

        cur.execute("UPDATE pm_vaults SET deleted_at = NULL WHERE id = %s", (vault_id,))

        log_admin_action(cur, g.current_uid, "vault_restore", vault["user_id"], f"Vault: {vault['vault_slug']}")
        conn.commit()

        app.logger.info(f"[ADMIN] User {g.current_uid} restored vault {vault_id}")
        return jsonify(success=True, message="Vault restored"), 200
    except Exception:
        app.logger.exception("[ADMIN_VAULT_RESTORE] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/admin/vaults/<int:vault_id>/purge", methods=["POST"])
@jwt_required
@admin_required
def admin_vault_purge(vault_id: int):
    """Permanently delete a vault (danger!)"""
    data = request.get_json(silent=True) or {}
    confirm = data.get("confirm")

    if confirm != "PURGE":
        return jsonify(success=False, message="Must confirm with {\"confirm\": \"PURGE\"}"), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute("SELECT user_id, vault_slug FROM pm_vaults WHERE id = %s", (vault_id,))
        vault = cur.fetchone()
        if not vault:
            return jsonify(success=False, message="Vault not found"), 404

        cur.execute("DELETE FROM pm_vaults WHERE id = %s", (vault_id,))

        log_admin_action(cur, g.current_uid, "vault_purge", vault["user_id"], f"Vault: {vault['vault_slug']} PERMANENTLY DELETED")
        conn.commit()

        app.logger.warning(f"[ADMIN] User {g.current_uid} PURGED vault {vault_id}")
        return jsonify(success=True, message="Vault permanently deleted"), 200
    except Exception:
        app.logger.exception("[ADMIN_VAULT_PURGE] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


# ---------- ADMIN: AUDIT LOG & NOTES ----------

@app.route("/api/admin/audit", methods=["GET"])
@jwt_required
@admin_required
def admin_audit_log():
    """Get admin audit log"""
    user_id = request.args.get("user_id", type=int)
    admin_id = request.args.get("admin_id", type=int)
    action = request.args.get("action")
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        query = """
            SELECT a.id, a.admin_uid, u.username AS admin_username,
                   a.action, a.target_user_id, t.username AS target_username,
                   a.details, a.created_at
            FROM pm_admin_audit a
            JOIN pm_users u ON u.uid = a.admin_uid
            LEFT JOIN pm_users t ON t.uid = a.target_user_id
            WHERE 1=1
        """
        params = []

        if user_id:
            query += " AND a.target_user_id = %s"
            params.append(user_id)
        if admin_id:
            query += " AND a.admin_uid = %s"
            params.append(admin_id)
        if action:
            query += " AND a.action = %s"
            params.append(action)

        query += " ORDER BY a.created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        cur.execute(query, tuple(params))
        logs = cur.fetchall() or []

        for log in logs:
            if log.get("created_at"):
                log["created_at"] = _as_utc(log["created_at"]).isoformat().replace("+00:00", "Z")

        return jsonify(success=True, logs=logs), 200
    except Exception:
        app.logger.exception("[ADMIN_AUDIT_LOG] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/admin/users/<int:uid>/notes", methods=["GET"])
@jwt_required
@admin_required
def admin_user_notes(uid: int):
    """Get admin notes for user"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            """
            SELECT n.id, n.note, n.created_at, u.username AS admin_username
            FROM pm_admin_notes n
            JOIN pm_users u ON u.uid = n.admin_uid
            WHERE n.user_id = %s
            ORDER BY n.created_at DESC
            """,
            (uid,)
        )
        notes = cur.fetchall() or []

        for n in notes:
            if n.get("created_at"):
                n["created_at"] = _as_utc(n["created_at"]).isoformat().replace("+00:00", "Z")

        return jsonify(success=True, notes=notes), 200
    except Exception:
        app.logger.exception("[ADMIN_USER_NOTES] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/admin/users/<int:uid>/notes", methods=["POST"])
@jwt_required
@admin_required
def admin_user_note_add(uid: int):
    """Add admin note to user"""
    data = request.get_json(silent=True) or {}
    note = (data.get("note") or "").strip()

    if not note:
        return jsonify(success=False, message="Note is required"), 400

    if len(note) > 2000:
        return jsonify(success=False, message="Note too long (max 2000 chars)"), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT uid FROM pm_users WHERE uid = %s", (uid,))
        if not cur.fetchone():
            return jsonify(success=False, message="User not found"), 404

        cur.execute(
            """
            INSERT INTO pm_admin_notes (user_id, admin_uid, note, created_at)
            VALUES (%s, %s, %s, NOW())
            """,
            (uid, g.current_uid, note)
        )

        log_admin_action(cur, g.current_uid, "note_add", uid, note[:100])
        conn.commit()

        app.logger.info(f"[ADMIN] User {g.current_uid} added note to user {uid}")
        return jsonify(success=True, message="Note added"), 201
    except Exception:
        app.logger.exception("[ADMIN_NOTE_ADD] Error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


# ============================================================
# ZERO-KNOWLEDGE VAULT SYNC & E2E SHARING
# ============================================================

# Import production-ready vault sync routes
from vault_sync_routes import register_vault_routes

# Register all vault sync, key management, and sharing routes
register_vault_routes(app, jwt_required, get_db_connection, app.logger)

# ---------- Run ----------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
