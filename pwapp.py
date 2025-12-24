from pathlib import Path 
from dotenv import load_dotenv
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, abort, g
import mysql.connector
from mysql.connector import Error as MySQLError
import bcrypt
import os
import logging
from functools import wraps
import jwt
import hashlib
import secrets

app = Flask(__name__)
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False

# ---------- Helpers / Env ----------

def _require_env(name: str) -> str:
    val = os.getenv(name)
    if not val:
        abort(500, description=f"Missing required environment variable: {name}")
    return val

def get_db_connection():
    return mysql.connector.connect(
        host=_require_env("DB_HOST"),
        user=_require_env("DB_USER"),
        password=_require_env("DB_PASSWORD"),
        database=_require_env("DB_NAME"),
    )

# ---------- JWT config ----------

JWT_SECRET = _require_env("JWT_SECRET")
JWT_ALGO = os.getenv("JWT_ALGO", "HS256")
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", "60"))

JWT_ISSUER = os.getenv("JWT_ISSUER", "modloader-api")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "modloader-clients")

# MOD DOWNLOAD BASE URL
MOD_BASE_URL = _require_env("MOD_BASE_URL")

# ---------- Refresh Token Config ----------
REFRESH_EXP_DAYS = int(os.getenv("REFRESH_EXP_DAYS", "30"))

BANNED_GROUP_IDS = {
    int(x) for x in os.getenv("BANNED_GROUP_IDS", "7").split(",") if x.strip().isdigit()
}

VIP_GROUP_IDS = {
    int(x) for x in os.getenv("VIP_GROUP_IDS", "4").split(",") if x.strip().isdigit()
}

REQUIRE_VIP_FOR_LOGIN = os.getenv("REQUIRE_VIP_FOR_LOGIN", "1") == "1"


# ---------- JWT helpers ----------

def create_access_token(uid: int, username: str, is_vip: bool) -> str:
    """Create a signed JWT for the user."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(uid),
        "username": username,
        "vip": bool(is_vip),
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
    """Decorator to protect routes with JWT bearer token."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            abort(401, description="Missing or invalid Authorization header")

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
            abort(401, description="Token expired")
        except jwt.InvalidTokenError:
            abort(401, description="Invalid token")

        g.jwt_payload = payload
        g.current_uid = int(payload.get("sub", 0))
        g.current_username = payload.get("username")
        g.current_is_vip = payload.get("vip", False)

        return fn(*args, **kwargs)
    return wrapper


# ---------- Utility Helpers ----------

def hash_hwid(hwid: str) -> str:
    return hashlib.sha256(hwid.encode("utf-8")).hexdigest()

def generate_refresh_token() -> tuple[str, str]:
    raw = secrets.token_hex(32)
    hashed = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return raw, hashed

def parse_group_list(group_str: str | None) -> set[int]:
    if not group_str:
        return set()
    return {
        int(x)
        for x in (g.strip() for g in group_str.split(","))
        if x.isdigit()
    }


def _get_user_and_groups(cur, uid: int):
    """
    Load usergroup + additionalgroups for this uid and return:
    (user_row_dict, set_of_all_group_ids)

    Returns (None, set()) if user not found.
    """
    cur.execute(
        """
        SELECT usergroup, additionalgroups
        FROM myhcc_users
        WHERE uid = %s
        LIMIT 1
        """,
        (uid,),
    )
    row = cur.fetchone()
    if not row:
        return None, set()

    primary_group = int(row.get("usergroup") or 0)
    additional_groups = parse_group_list(row.get("additionalgroups"))
    all_groups = {primary_group} | additional_groups
    return row, all_groups


def _compute_allowed_mod_ids(cur, uid: int, all_groups: set[int]) -> set[int]:
    """
    Compute the set of mod_ids this user is allowed to use, based on
    myhcc_mod_entitlements.

    Rules:
      - Any entry with allowed=0 is an explicit deny and overrides allows.
      - At least one allowed=1 is required to grant access.
      - If there are no entitlements, returns an empty set.
    """
    params = [uid]
    entitlement_sql = """
        SELECT mod_id, user_id, group_id, allowed
        FROM myhcc_mod_entitlements
        WHERE user_id = %s
    """

    if all_groups:
        in_clause = ",".join(["%s"] * len(all_groups))
        entitlement_sql += f" OR group_id IN ({in_clause})"
        params.extend(list(all_groups))

    cur.execute(entitlement_sql, params)
    ent_rows = cur.fetchall()

    allowed_mods = set()
    denied_mods = set()

    for row in ent_rows:
        mod_id = int(row["mod_id"])
        is_allowed = bool(row.get("allowed", 1))

        if not is_allowed:
            # explicit deny wins
            denied_mods.add(mod_id)
            if mod_id in allowed_mods:
                allowed_mods.remove(mod_id)
            continue

        if mod_id not in denied_mods:
            allowed_mods.add(mod_id)

    return allowed_mods


# ---------- Error handlers (always JSON) ----------

@app.errorhandler(400)
def _bad_request(e):
    return jsonify(success=False, message=str(e.description or "Bad request")), 400

@app.errorhandler(401)
def _unauth(e):
    return jsonify(success=False, message=str(e.description or "Unauthorized")), 401

@app.errorhandler(500)
def _server_error(e):
    return jsonify(success=False, message="Server error"), 500


app.logger.setLevel(logging.INFO)

# ---------- Health checks ----------

@app.route("/api/ping")
def ping():
    return jsonify(ok=True)

@app.route("/api/dbcheck")
def dbcheck():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        cur.close()
        conn.close()
        return jsonify(ok=True)
    except Exception as ex:
        app.logger.exception("[DBCHECK] DB connectivity failed")
        return jsonify(ok=False, error=str(ex)), 500


# ---------- Mods (JWT-protected) ----------

@app.route("/api/mods", methods=["GET"])
@jwt_required
def list_mods():
    """
    Return mods the current user is entitled to use for a given game.
    Uses myhcc_mod_entitlements to determine allowed mod_ids.
    """
    game = (request.args.get("game") or "").strip().upper()
    if not game:
        abort(400, description="Missing game parameter")

    uid = g.current_uid

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        # 1) User + groups
        user_row, all_groups = _get_user_and_groups(cur, uid)
        if not user_row:
            return jsonify(success=False, message="User not found"), 401

        # 2) Allowed mod ids from entitlements
        allowed_mods = _compute_allowed_mod_ids(cur, uid, all_groups)
        if not allowed_mods:
            # No entitlements -> no mods
            return jsonify(success=True, mods=[]), 200

        mod_id_list = sorted(allowed_mods)
        in_clause = ",".join(["%s"] * len(mod_id_list))
        params = [game] + mod_id_list

        # 3) Actually load mod metadata
        cur.execute(
            f"""
            SELECT id, game, name, internal_name, version, file_path, sha256
            FROM myhcc_mods
            WHERE game = %s
              AND is_active = 1
              AND id IN ({in_clause})
            ORDER BY name ASC
            """,
            params,
        )
        rows = cur.fetchall()

        mods = []
        for r in rows:
            download_url = f"{MOD_BASE_URL}/{r['file_path']}"
            mods.append({
                "id": r["id"],
                "game": r["game"],
                "name": r["name"],
                "internal_name": r["internal_name"],
                "version": r["version"],
                "download_url": download_url,
                "sha256": r["sha256"],
            })

        return jsonify(success=True, mods=mods), 200

    except Exception:
        app.logger.exception("[MODS] Unhandled error (with entitlements)")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route("/api/mods/download/<mod_key>", methods=["GET"])
@jwt_required
def download_mod(mod_key: str):
    """
    Download endpoint with entitlement + logging.

    - mod_key can be:
        * numeric -> myhcc_mods.id
        * non-numeric -> myhcc_mods.internal_name
    - Requires ?hwid=... query parameter.
    """
    hwid = (request.args.get("hwid") or "").strip()
    if not hwid:
        return jsonify(success=False, message="Missing hwid parameter"), 400

    uid = g.current_uid
    hwid_hash = hash_hwid(hwid)
    is_numeric_id = mod_key.isdigit()

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        # 1) User + groups
        user_row, all_groups = _get_user_and_groups(cur, uid)
        if not user_row:
            return jsonify(success=False, message="User not found"), 401

        # 2) Allowed mod ids for this user
        allowed_mods = _compute_allowed_mod_ids(cur, uid, all_groups)

        # 3) Load the mod row by id or internal_name
        if is_numeric_id:
            cur.execute(
                """
                SELECT id, game, name, internal_name, version, file_path, sha256, is_active
                FROM myhcc_mods
                WHERE id = %s
                LIMIT 1
                """,
                (int(mod_key),),
            )
        else:
            cur.execute(
                """
                SELECT id, game, name, internal_name, version, file_path, sha256, is_active
                FROM myhcc_mods
                WHERE internal_name = %s
                LIMIT 1
                """,
                (mod_key,),
            )

        mod = cur.fetchone()
        if not mod:
            return jsonify(success=False, message="Mod not found"), 404

        mod_id = int(mod["id"])

        # 4) Check entitlements via allowed_mods set
        if mod_id not in allowed_mods or not mod.get("is_active"):
            ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
            user_agent = request.headers.get("User-Agent", "")[:255]

            cur.execute(
                """
                INSERT INTO myhcc_download_log
                    (user_id, mod_id, hwid_hash,
                     ip_address, user_agent, status, downloaded_at)
                VALUES (%s, %s, %s, %s, %s, 'blocked', NOW())
                """,
                (uid, mod_id, hwid_hash, ip_address, user_agent),
            )
            conn.commit()

            return jsonify(success=False, message="Not entitled or mod inactive"), 403

        # 5) Log successful download attempt
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        user_agent = request.headers.get("User-Agent", "")[:255]

        cur.execute(
            """
            INSERT INTO myhcc_download_log
                (user_id, mod_id, hwid_hash,
                 ip_address, user_agent, status, downloaded_at)
            VALUES (%s, %s, %s, %s, %s, 'success', NOW())
            """,
            (uid, mod_id, hwid_hash, ip_address, user_agent),
        )
        conn.commit()

        # 6) Return download info
        download_url = f"{MOD_BASE_URL}/{mod['file_path']}"

        return jsonify(
            success=True,
            mod={
                "id": mod["id"],
                "game": mod["game"],
                "name": mod["name"],
                "internal_name": mod["internal_name"],
                "version": mod["version"],
                "download_url": download_url,
                "sha256": mod["sha256"],
            }
        ), 200

    except MySQLError:
        app.logger.exception("[MODS_DOWNLOAD] MySQL error")
        return jsonify(success=False, message="Service unavailable"), 503
    except Exception:
        app.logger.exception("[MODS_DOWNLOAD] Unhandled server error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


# ---------- AUTH LOGIN (MAIN LOADER LOGIN ENDPOINT) ----------

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "")
    hwid = (data.get("hwid") or "").strip()

    if not username or not password or not hwid:
        return jsonify(success=False, message="Missing username, password, or hwid"), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        # 1) Load user from MyBB users table (bcrypt hashed)
        cur.execute(
            """
            SELECT
                uid,
                username,
                password,
                usergroup,
                additionalgroups,
                ougc_invite_system_banned
            FROM myhcc_users
            WHERE username = %s
            LIMIT 1
            """,
            (username,),
        )
        user = cur.fetchone()

        if not user:
            return jsonify(success=False, message="Invalid username or password"), 401

        uid = int(user["uid"])
        stored_hash = user.get("password")

        if stored_hash is None:
            app.logger.warning("[AUTH_LOGIN] Stored hash is NULL for username=%s", username)
            return jsonify(success=False, message="Invalid username or password"), 401

        # Make sure stored hash is bytes
        if isinstance(stored_hash, str):
            stored_hash_bytes = stored_hash.encode("utf-8")
        else:
            stored_hash_bytes = stored_hash

        # 2) Verify bcrypt password
        try:
            ok = bcrypt.checkpw(password.encode("utf-8"), stored_hash_bytes)
        except Exception:
            app.logger.exception("[AUTH_LOGIN] bcrypt failure for username=%s", username)
            return jsonify(success=False, message="Invalid username or password"), 401

        if not ok:
            return jsonify(success=False, message="Invalid username or password"), 401

        # 3) Check VIP/banned
        usergroup = int(user.get("usergroup") or 0)
        additionalgroups = parse_group_list(user.get("additionalgroups"))
        all_groups = {usergroup} | additionalgroups

        is_banned_flag = bool(user.get("ougc_invite_system_banned"))
        is_banned_group = any(g in BANNED_GROUP_IDS for g in all_groups)
        is_vip = any(g in VIP_GROUP_IDS for g in all_groups)

        if is_banned_flag or is_banned_group:
            return jsonify(success=False, message="Account banned"), 403

        if REQUIRE_VIP_FOR_LOGIN and not is_vip:
            return jsonify(success=False, message="Account not invited/VIP"), 403

        # 4) HWID hash
        hwid_hash = hash_hwid(hwid)

        # 5) Enforce single-HWID: revoke old tokens with different HWID
        cur.execute(
            """
            SELECT id, hwid_hash
            FROM myhcc_auth_refresh_tokens
            WHERE user_id = %s
              AND revoked_at IS NULL
            """,
            (uid,),
        )
        existing_tokens = cur.fetchall()

        for row in existing_tokens:
            if row["hwid_hash"] != hwid_hash:
                cur.execute(
                    """
                    UPDATE myhcc_auth_refresh_tokens
                    SET revoked_at = NOW(), reason = 'hwid_mismatch'
                    WHERE id = %s
                    """,
                    (row["id"],),
                )

        # 6) Create & store new refresh token
        raw_refresh, hashed_refresh = generate_refresh_token()
        expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_EXP_DAYS)

        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        user_agent = request.headers.get("User-Agent", "")[:255]

        cur.execute(
            """
            INSERT INTO myhcc_auth_refresh_tokens
                (user_id, refresh_token_hash, hwid_hash,
                 created_at, expires_at,
                 ip_address, user_agent, reason)
            VALUES (%s, %s, %s, NOW(), %s, %s, %s, 'login')
            """,
            (uid, hashed_refresh, hwid_hash, expires_at, ip_address, user_agent),
        )

        conn.commit()

        # 7) Issue access token JWT
        access_token = create_access_token(uid=uid, username=user["username"], is_vip=is_vip)

        return jsonify(
            success=True,
            uid=uid,
            username=user["username"],
            is_vip=is_vip,
            access_token=access_token,
            access_expires_in=JWT_EXP_MINUTES * 60,
            refresh_token=raw_refresh,
            refresh_expires_in=REFRESH_EXP_DAYS * 86400,
        ), 200

    except MySQLError:
        app.logger.exception("[AUTH_LOGIN] MySQL error")
        return jsonify(success=False, message="Service unavailable"), 503
    except Exception:
        app.logger.exception("[AUTH_LOGIN] Unhandled server error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# ---------- AUTH REFRESH  ----------

@app.route("/api/auth/refresh", methods=["POST"])
def auth_refresh():
    data = request.get_json(silent=True) or {}
    raw_refresh = (data.get("refresh_token") or "").strip()
    hwid = (data.get("hwid") or "").strip()

    if not raw_refresh or not hwid:
        return jsonify(success=False, message="Missing refresh_token or hwid"), 400

    hashed_refresh = hashlib.sha256(raw_refresh.encode("utf-8")).hexdigest()
    hwid_hash = hash_hwid(hwid)

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        # 1) Find refresh token row + join user
        cur.execute(
            """
            SELECT
                t.id,
                t.user_id,
                t.hwid_hash,
                t.expires_at,
                t.revoked_at,
                u.username,
                u.usergroup,
                u.additionalgroups,
                u.ougc_invite_system_banned
            FROM myhcc_auth_refresh_tokens AS t
            JOIN myhcc_users AS u
              ON u.uid = t.user_id
            WHERE t.refresh_token_hash = %s
            LIMIT 1
            """,
            (hashed_refresh,),
        )
        row = cur.fetchone()

        if not row:
            # Unknown token
            return jsonify(success=False, message="Invalid refresh token"), 401

        token_id = int(row["id"])
        uid = int(row["user_id"])
        db_hwid_hash = row["hwid_hash"]
        expires_at = row["expires_at"]
        revoked_at = row["revoked_at"]

        # 2) Basic validity checks
        now = datetime.now(timezone.utc)

        if revoked_at is not None:
            return jsonify(success=False, message="Refresh token revoked"), 401

        if isinstance(expires_at, datetime):
            # If DB stores naive datetimes, you may want to treat them as UTC
            if expires_at.replace(tzinfo=timezone.utc) <= now:
                return jsonify(success=False, message="Refresh token expired"), 401

        if db_hwid_hash != hwid_hash:
            # HWID mismatch -> revoke token
            cur.execute(
                """
                UPDATE myhcc_auth_refresh_tokens
                SET revoked_at = NOW(), reason = 'hwid_mismatch_refresh'
                WHERE id = %s
                """,
                (token_id,),
            )
            conn.commit()
            return jsonify(success=False, message="Invalid refresh token"), 401

        # 3) Re-check VIP / banned status from MyBB groups
        usergroup = int(row.get("usergroup") or 0)
        additionalgroups = parse_group_list(row.get("additionalgroups"))
        all_groups = {usergroup} | additionalgroups

        is_banned_flag = bool(row.get("ougc_invite_system_banned"))
        is_banned_group = any(g in BANNED_GROUP_IDS for g in all_groups)
        is_vip = any(g in VIP_GROUP_IDS for g in all_groups)

        if is_banned_flag or is_banned_group:
            # Kill this token as well
            cur.execute(
                """
                UPDATE myhcc_auth_refresh_tokens
                SET revoked_at = NOW(), reason = 'banned_on_refresh'
                WHERE id = %s
                """,
                (token_id,),
            )
            conn.commit()
            return jsonify(success=False, message="Account banned"), 403

        if REQUIRE_VIP_FOR_LOGIN and not is_vip:
            cur.execute(
                """
                UPDATE myhcc_auth_refresh_tokens
                SET revoked_at = NOW(), reason = 'lost_vip_on_refresh'
                WHERE id = %s
                """,
                (token_id,),
            )
            conn.commit()
            return jsonify(success=False, message="Account not invited/VIP"), 403

        # 4) Rotate refresh token: revoke old, insert new
        new_raw_refresh, new_hashed_refresh = generate_refresh_token()
        new_expires_at = now + timedelta(days=REFRESH_EXP_DAYS)

        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        user_agent = request.headers.get("User-Agent", "")[:255]

        # Revoke old one as "rotated"
        cur.execute(
            """
            UPDATE myhcc_auth_refresh_tokens
            SET revoked_at = NOW(), reason = 'rotated'
            WHERE id = %s
            """,
            (token_id,),
        )

        # Insert new one
        cur.execute(
            """
            INSERT INTO myhcc_auth_refresh_tokens
                (user_id, refresh_token_hash, hwid_hash,
                 created_at, expires_at, ip_address, user_agent, reason)
            VALUES (%s, %s, %s, NOW(), %s, %s, %s, 'refresh')
            """,
            (uid, new_hashed_refresh, hwid_hash, new_expires_at, ip_address, user_agent),
        )

        conn.commit()

        # 5) Issue new access token
        access_token = create_access_token(
            uid=uid,
            username=row["username"],
            is_vip=is_vip,
        )

        return jsonify(
            success=True,
            uid=uid,
            username=row["username"],
            is_vip=is_vip,
            access_token=access_token,
            access_expires_in=JWT_EXP_MINUTES * 60,
            refresh_token=new_raw_refresh,
            refresh_expires_in=REFRESH_EXP_DAYS * 86400,
        ), 200

    except MySQLError:
        app.logger.exception("[AUTH_REFRESH] MySQL error")
        return jsonify(success=False, message="Service unavailable"), 503
    except Exception:
        app.logger.exception("[AUTH_REFRESH] Unhandled server error")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# ---------- Example protected endpoint ----------

@app.route("/api/me", methods=["GET"])
@jwt_required
def me():
    return jsonify(
        success=True,
        uid=g.current_uid,
        username=g.current_username,
        vip=g.current_is_vip,
    ), 200

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

# ---------- Run App ----------

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)