"""
Zero-Knowledge Vault Sync & E2E Sharing Routes
Production-ready implementation with:
- Binary checksums (BINARY(32))
- Base64 API encoding
- Strict validations
- Rate limiting
- Proper logging (no sensitive data)
"""

import base64
import hashlib
import re
import threading
from datetime import datetime, timezone
from flask import request, jsonify, g
from functools import wraps
from time import time as unix_time

# Constants
MAX_VAULT_SIZE = 10 * 1024 * 1024  # 10MB
MAX_SHARED_ITEM_SIZE = 1 * 1024 * 1024  # 1MB
MAX_VAULT_HISTORY = 10
MAX_RATE_LIMIT_KEYS = 10000

# Strict crypto sizes (libsodium)
PUBLIC_KEY_SIZE = 32  # X25519 public key
SEALED_KEY_SIZE = 80  # crypto_box_seal output
CHECKSUM_SIZE = 32  # SHA-256

# Vault slug pattern
VAULT_SLUG_PATTERN = re.compile(r'^[a-z0-9_-]+$')

# Rate limiting store (use Redis in production)
_rate_limit_store = {}
_rate_limit_lock = threading.Lock()

def _cleanup_rate_limit_store():
    """Remove expired entries from rate limit store"""
    now = unix_time()
    with _rate_limit_lock:
        expired_keys = [k for k, v in _rate_limit_store.items() if not v or max(v) < now - 3600]
        for k in expired_keys:
            del _rate_limit_store[k]

def rate_limit(key_fn, limit: int, window: int):
    """Simple rate limiter with cleanup to prevent memory leak"""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = key_fn()
            now = unix_time()

            with _rate_limit_lock:
                # Cleanup if too many keys
                if len(_rate_limit_store) > MAX_RATE_LIMIT_KEYS:
                    _cleanup_rate_limit_store()

                if key not in _rate_limit_store:
                    _rate_limit_store[key] = []

                # Filter expired timestamps
                _rate_limit_store[key] = [t for t in _rate_limit_store[key] if t > now - window]

                if len(_rate_limit_store[key]) >= limit:
                    return jsonify(success=False, message="Rate limit exceeded"), 429

                _rate_limit_store[key].append(now)

            return fn(*args, **kwargs)
        return wrapper
    return decorator

def compute_checksum(data: bytes) -> bytes:
    """SHA-256 checksum (returns raw 32 bytes)"""
    return hashlib.sha256(data).digest()

def validate_vault_slug(slug: str) -> bool:
    """Validate vault slug: lowercase, numbers, hyphens, underscores, max 64 chars"""
    if not slug or len(slug) > 64:
        return False
    return bool(VAULT_SLUG_PATTERN.match(slug))

def _as_utc(dt: datetime) -> datetime:
    """Convert datetime to UTC"""
    if not isinstance(dt, datetime):
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def register_vault_routes(app, jwt_required, get_db_connection, logger):
    """Register all vault sync routes to Flask app"""

    # ============================================================
    # VAULT SYNC ENDPOINTS
    # ============================================================

    @app.route("/api/pm/vault", methods=["GET"])
    @jwt_required
    @rate_limit(lambda: f"vault_list:{g.current_uid}", limit=60, window=60)
    def vault_list():
        """List user's vaults (metadata only, no blobs)"""
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)

            cur.execute(
                """
                SELECT vault_slug, vault_name, current_version, current_checksum, updated_at, created_at
                FROM pm_vaults
                WHERE user_id = %s
                ORDER BY vault_slug
                """,
                (g.current_uid,)
            )
            vaults = cur.fetchall() or []

            for v in vaults:
                # Encode binary checksum to base64
                v["current_checksum"] = base64.b64encode(v["current_checksum"]).decode("utf-8")
                if v.get("updated_at"):
                    v["updated_at"] = _as_utc(v["updated_at"]).isoformat().replace("+00:00", "Z")
                if v.get("created_at"):
                    v["created_at"] = _as_utc(v["created_at"]).isoformat().replace("+00:00", "Z")

            logger.info(f"[VAULT_LIST] User {g.current_uid} listed {len(vaults)} vaults")
            return jsonify(success=True, vaults=vaults), 200

        except Exception:
            logger.exception("[VAULT_LIST] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @app.route("/api/pm/vault/<vault_slug>/head", methods=["GET"])
    @jwt_required
    @rate_limit(lambda: f"vault_head:{g.current_uid}", limit=120, window=60)
    def vault_head(vault_slug: str):
        """Get vault metadata for sync check"""
        if not validate_vault_slug(vault_slug):
            return jsonify(success=False, message="Invalid vault slug"), 400

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)

            cur.execute(
                """
                SELECT current_version, current_checksum, updated_at
                FROM pm_vaults
                WHERE user_id = %s AND vault_slug = %s
                LIMIT 1
                """,
                (g.current_uid, vault_slug)
            )
            vault = cur.fetchone()

            if not vault:
                return jsonify(success=False, message="Vault not found"), 404

            return jsonify(
                success=True,
                version=vault["current_version"],
                checksum=base64.b64encode(vault["current_checksum"]).decode("utf-8"),
                updated_at=_as_utc(vault["updated_at"]).isoformat().replace("+00:00", "Z")
            ), 200

        except Exception:
            logger.exception("[VAULT_HEAD] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @app.route("/api/pm/vault/<vault_slug>", methods=["GET"])
    @jwt_required
    @rate_limit(lambda: f"vault_get:{g.current_uid}", limit=30, window=60)
    def vault_get(vault_slug: str):
        """Download vault blob (current or specific version)"""
        if not validate_vault_slug(vault_slug):
            return jsonify(success=False, message="Invalid vault slug"), 400

        version_param = request.args.get("version")

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)

            # Get vault ID
            cur.execute(
                """
                SELECT id, current_version, current_checksum, vault_data
                FROM pm_vaults
                WHERE user_id = %s AND vault_slug = %s
                LIMIT 1
                """,
                (g.current_uid, vault_slug)
            )
            vault = cur.fetchone()

            if not vault:
                return jsonify(success=False, message="Vault not found"), 404

            if version_param:
                # Get specific version from history
                cur.execute(
                    """
                    SELECT version, checksum, vault_data
                    FROM pm_vault_versions
                    WHERE vault_id = %s AND version = %s
                    LIMIT 1
                    """,
                    (vault["id"], int(version_param))
                )
                hist = cur.fetchone()
                if not hist:
                    return jsonify(success=False, message="Version not found"), 404

                logger.info(f"[VAULT_GET] User {g.current_uid} downloaded {vault_slug} v{hist['version']} ({len(hist['vault_data'])} bytes)")
                return jsonify(
                    success=True,
                    blob=base64.b64encode(hist["vault_data"]).decode("utf-8"),
                    version=hist["version"],
                    checksum=base64.b64encode(hist["checksum"]).decode("utf-8")
                ), 200
            else:
                # Get current version
                logger.info(f"[VAULT_GET] User {g.current_uid} downloaded {vault_slug} v{vault['current_version']} ({len(vault['vault_data'])} bytes)")
                return jsonify(
                    success=True,
                    blob=base64.b64encode(vault["vault_data"]).decode("utf-8"),
                    version=vault["current_version"],
                    checksum=base64.b64encode(vault["current_checksum"]).decode("utf-8")
                ), 200

        except Exception:
            logger.exception("[VAULT_GET] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @app.route("/api/pm/vault/<vault_slug>", methods=["PUT"])
    @jwt_required
    @rate_limit(lambda: f"vault_put:{g.current_uid}", limit=60, window=3600)
    def vault_put(vault_slug: str):
        """Upload or update vault with optimistic locking"""
        if not validate_vault_slug(vault_slug):
            return jsonify(success=False, message="Invalid vault slug"), 400

        # Size limit check
        if request.content_length and request.content_length > 15 * 1024 * 1024:
            return jsonify(success=False, message="Request too large"), 413

        data = request.get_json(silent=True) or {}
        blob_b64 = data.get("blob", "")
        vault_name = data.get("vault_name", "My Vault")
        expected_version = data.get("expected_version")
        checksum_b64 = data.get("checksum", "")

        if not blob_b64:
            return jsonify(success=False, message="blob is required"), 400

        # Decode blob
        try:
            blob_bytes = base64.b64decode(blob_b64)
        except Exception:
            return jsonify(success=False, message="Invalid base64 blob"), 400

        if len(blob_bytes) > MAX_VAULT_SIZE:
            return jsonify(success=False, message=f"Vault too large (max {MAX_VAULT_SIZE} bytes)"), 400

        # Decode and validate checksum
        try:
            checksum_bytes = base64.b64decode(checksum_b64)
        except Exception:
            return jsonify(success=False, message="Invalid base64 checksum"), 400

        if len(checksum_bytes) != CHECKSUM_SIZE:
            return jsonify(success=False, message=f"Checksum must be {CHECKSUM_SIZE} bytes"), 400

        # Verify checksum
        actual_checksum = compute_checksum(blob_bytes)
        if actual_checksum != checksum_bytes:
            return jsonify(success=False, message="Checksum mismatch"), 400

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)

            # Check existing vault
            cur.execute(
                """
                SELECT id, current_version, vault_data, current_checksum
                FROM pm_vaults
                WHERE user_id = %s AND vault_slug = %s
                LIMIT 1
                """,
                (g.current_uid, vault_slug)
            )
            existing = cur.fetchone()

            if existing:
                # Update: check version
                if expected_version is None:
                    return jsonify(success=False, message="expected_version required for update"), 400

                if existing["current_version"] != expected_version:
                    return jsonify(
                        success=False,
                        message="Version conflict",
                        server_version=existing["current_version"]
                    ), 409

                # Archive old version
                cur.execute(
                    """
                    INSERT INTO pm_vault_versions (vault_id, version, checksum, vault_data, created_at)
                    VALUES (%s, %s, %s, %s, NOW())
                    """,
                    (existing["id"], existing["current_version"], existing["current_checksum"], existing["vault_data"])
                )

                # Update vault
                new_version = existing["current_version"] + 1
                cur.execute(
                    """
                    UPDATE pm_vaults
                    SET vault_data = %s, current_version = %s, current_checksum = %s,
                        vault_name = %s, updated_at = NOW()
                    WHERE id = %s
                    """,
                    (blob_bytes, new_version, checksum_bytes, vault_name, existing["id"])
                )

                # Prune old history (keep last MAX_VAULT_HISTORY versions)
                cur.execute(
                    """
                    SELECT version FROM pm_vault_versions
                    WHERE vault_id = %s
                    ORDER BY version DESC
                    LIMIT 1 OFFSET %s
                    """,
                    (existing["id"], MAX_VAULT_HISTORY - 1)
                )
                cutoff_row = cur.fetchone()
                if cutoff_row:
                    cur.execute(
                        """
                        DELETE FROM pm_vault_versions
                        WHERE vault_id = %s AND version < %s
                        """,
                        (existing["id"], cutoff_row["version"])
                    )

                conn.commit()

                logger.info(f"[VAULT_PUT] User {g.current_uid} updated {vault_slug} v{existing['current_version']} -> v{new_version} ({len(blob_bytes)} bytes)")
                return jsonify(success=True, version=new_version, checksum=checksum_b64), 200

            else:
                # Create new vault
                cur.execute(
                    """
                    INSERT INTO pm_vaults (user_id, vault_slug, vault_name, vault_data, current_version, current_checksum, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, 1, %s, NOW(), NOW())
                    """,
                    (g.current_uid, vault_slug, vault_name, blob_bytes, checksum_bytes)
                )
                conn.commit()

                logger.info(f"[VAULT_PUT] User {g.current_uid} created {vault_slug} v1 ({len(blob_bytes)} bytes)")
                return jsonify(success=True, version=1, checksum=checksum_b64), 201

        except Exception:
            logger.exception("[VAULT_PUT] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @app.route("/api/pm/vault/<vault_slug>/history", methods=["GET"])
    @jwt_required
    @rate_limit(lambda: f"vault_history:{g.current_uid}", limit=30, window=60)
    def vault_history(vault_slug: str):
        """Get vault version history"""
        if not validate_vault_slug(vault_slug):
            return jsonify(success=False, message="Invalid vault slug"), 400

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)

            # Get vault ID
            cur.execute(
                """
                SELECT id FROM pm_vaults
                WHERE user_id = %s AND vault_slug = %s
                LIMIT 1
                """,
                (g.current_uid, vault_slug)
            )
            vault = cur.fetchone()
            if not vault:
                return jsonify(success=False, message="Vault not found"), 404

            # List history
            cur.execute(
                """
                SELECT version, checksum, created_at
                FROM pm_vault_versions
                WHERE vault_id = %s
                ORDER BY version DESC
                LIMIT 20
                """,
                (vault["id"],)
            )
            history = cur.fetchall() or []

            for h in history:
                h["checksum"] = base64.b64encode(h["checksum"]).decode("utf-8")
                if h.get("created_at"):
                    h["created_at"] = _as_utc(h["created_at"]).isoformat().replace("+00:00", "Z")

            return jsonify(success=True, history=history), 200

        except Exception:
            logger.exception("[VAULT_HISTORY] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @app.route("/api/pm/vault/<vault_slug>", methods=["DELETE"])
    @jwt_required
    def vault_delete(vault_slug: str):
        """Delete vault and its history"""
        if not validate_vault_slug(vault_slug):
            return jsonify(success=False, message="Invalid vault slug"), 400

        confirm = request.args.get("confirm")
        if confirm != "true":
            return jsonify(success=False, message="Confirmation required (confirm=true)"), 400

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()

            # Delete vault (versions deleted by CASCADE)
            cur.execute(
                """
                DELETE FROM pm_vaults
                WHERE user_id = %s AND vault_slug = %s
                """,
                (g.current_uid, vault_slug)
            )
            deleted = cur.rowcount
            conn.commit()

            if deleted == 0:
                return jsonify(success=False, message="Vault not found"), 404

            logger.info(f"[VAULT_DELETE] User {g.current_uid} deleted {vault_slug}")
            return jsonify(success=True, message="Vault deleted"), 200

        except Exception:
            logger.exception("[VAULT_DELETE] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    # ============================================================
    # KEY MANAGEMENT ENDPOINTS
    # ============================================================

    @app.route("/api/pm/keys", methods=["POST"])
    @jwt_required
    def keys_upsert():
        """Upload/update user's public key (X25519)"""
        data = request.get_json(silent=True) or {}
        public_key_b64 = (data.get("public_key") or "").strip()
        key_type = (data.get("key_type") or "x25519").strip()

        if not public_key_b64:
            return jsonify(success=False, message="public_key is required"), 400

        # Decode and validate
        try:
            pk_bytes = base64.b64decode(public_key_b64)
        except Exception:
            return jsonify(success=False, message="Invalid base64 public key"), 400

        if len(pk_bytes) != PUBLIC_KEY_SIZE:
            return jsonify(success=False, message=f"Public key must be {PUBLIC_KEY_SIZE} bytes"), 400

        if key_type not in ("x25519", "ed25519"):
            return jsonify(success=False, message="Invalid key_type (must be x25519 or ed25519)"), 400

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute(
                """
                INSERT INTO pm_user_keys (user_id, public_key, key_type, created_at, updated_at)
                VALUES (%s, %s, %s, NOW(), NOW())
                ON DUPLICATE KEY UPDATE
                  public_key = VALUES(public_key),
                  key_type = VALUES(key_type),
                  updated_at = NOW()
                """,
                (g.current_uid, pk_bytes, key_type)
            )
            conn.commit()

            logger.info(f"[KEYS_UPSERT] User {g.current_uid} uploaded {key_type} key")
            return jsonify(success=True, message="Public key saved"), 200

        except Exception:
            logger.exception("[KEYS_UPSERT] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @app.route("/api/pm/keys", methods=["GET"])
    @jwt_required
    def keys_get_own():
        """Get own public key"""
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)

            cur.execute(
                """
                SELECT public_key, key_type, created_at
                FROM pm_user_keys
                WHERE user_id = %s
                LIMIT 1
                """,
                (g.current_uid,)
            )
            key = cur.fetchone()

            if not key:
                return jsonify(success=False, message="No public key found"), 404

            return jsonify(
                success=True,
                public_key=base64.b64encode(key["public_key"]).decode("utf-8"),
                key_type=key["key_type"],
                created_at=_as_utc(key["created_at"]).isoformat().replace("+00:00", "Z") if key.get("created_at") else None
            ), 200

        except Exception:
            logger.exception("[KEYS_GET_OWN] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @app.route("/api/pm/keys/lookup", methods=["GET"])
    @jwt_required
    def keys_lookup():
        """Look up another user's public key by email or username"""
        email = request.args.get("email", "").strip().lower()
        username = request.args.get("username", "").strip()

        if not email and not username:
            return jsonify(success=False, message="email or username parameter required"), 400

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)

            if email:
                cur.execute(
                    """
                    SELECT u.uid, u.username, k.public_key, k.key_type
                    FROM pm_users u
                    JOIN pm_user_keys k ON k.user_id = u.uid
                    WHERE u.email = %s
                    LIMIT 1
                    """,
                    (email,)
                )
            else:
                cur.execute(
                    """
                    SELECT u.uid, u.username, k.public_key, k.key_type
                    FROM pm_users u
                    JOIN pm_user_keys k ON k.user_id = u.uid
                    WHERE u.username = %s
                    LIMIT 1
                    """,
                    (username,)
                )

            user = cur.fetchone()

            if not user:
                return jsonify(success=False, message="User not found or no public key"), 404

            return jsonify(
                success=True,
                user_id=user["uid"],
                username=user["username"],
                public_key=base64.b64encode(user["public_key"]).decode("utf-8"),
                key_type=user["key_type"]
            ), 200

        except Exception:
            logger.exception("[KEYS_LOOKUP] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    # ============================================================
    # SHARING ENDPOINTS
    # ============================================================

    @app.route("/api/pm/share/item", methods=["POST"])
    @jwt_required
    @rate_limit(lambda: f"share_create:{g.current_uid}", limit=20, window=60)
    def share_create():
        """Share encrypted item with recipients"""
        if request.content_length and request.content_length > 2 * 1024 * 1024:
            return jsonify(success=False, message="Request too large"), 413

        data = request.get_json(silent=True) or {}
        encrypted_data_b64 = data.get("encrypted_data", "")
        checksum_b64 = data.get("checksum", "")
        grants = data.get("grants", [])
        expires_at_str = data.get("expires_at")

        if not encrypted_data_b64:
            return jsonify(success=False, message="encrypted_data is required"), 400

        # Decode encrypted_data
        try:
            encrypted_bytes = base64.b64decode(encrypted_data_b64)
        except Exception:
            return jsonify(success=False, message="Invalid base64 encrypted_data"), 400

        if len(encrypted_bytes) > MAX_SHARED_ITEM_SIZE:
            return jsonify(success=False, message=f"Item too large (max {MAX_SHARED_ITEM_SIZE} bytes)"), 400

        # Decode checksum
        try:
            checksum_bytes = base64.b64decode(checksum_b64)
        except Exception:
            return jsonify(success=False, message="Invalid base64 checksum"), 400

        if len(checksum_bytes) != CHECKSUM_SIZE:
            return jsonify(success=False, message=f"Checksum must be {CHECKSUM_SIZE} bytes"), 400

        # Verify checksum
        actual_checksum = compute_checksum(encrypted_bytes)
        if actual_checksum != checksum_bytes:
            return jsonify(success=False, message="Checksum mismatch"), 400

        if not grants or not isinstance(grants, list):
            return jsonify(success=False, message="grants array is required"), 400

        # Parse expires_at
        expires_at = None
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
                expires_at = _as_utc(expires_at)
            except Exception:
                return jsonify(success=False, message="Invalid expires_at format"), 400

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)

            # Validate all recipient IDs exist
            recipient_ids = [int(g.get("recipient_id")) for g in grants if g.get("recipient_id")]
            if recipient_ids:
                placeholders = ",".join(["%s"] * len(recipient_ids))
                cur.execute(f"SELECT uid FROM pm_users WHERE uid IN ({placeholders})", tuple(recipient_ids))
                valid_ids = {row["uid"] for row in cur.fetchall()}

                # Filter grants to valid recipients only
                grants = [g for g in grants if int(g.get("recipient_id", 0)) in valid_ids]

            if not grants:
                return jsonify(success=False, message="No valid recipients"), 400

            # Create shared item
            cur.execute(
                """
                INSERT INTO pm_shared_items (owner_id, encrypted_data, checksum, created_at, expires_at)
                VALUES (%s, %s, %s, NOW(), %s)
                """,
                (g.current_uid, encrypted_bytes, checksum_bytes, expires_at)
            )
            item_id = cur.lastrowid

            # Create grants
            grants_created = 0
            for grant in grants:
                recipient_id = grant.get("recipient_id")
                sealed_key_b64 = (grant.get("sealed_key") or "").strip()

                if not recipient_id or not sealed_key_b64:
                    continue

                # Decode sealed_key
                try:
                    sealed_key_bytes = base64.b64decode(sealed_key_b64)
                except Exception:
                    continue

                if len(sealed_key_bytes) != SEALED_KEY_SIZE:
                    continue

                try:
                    cur.execute(
                        """
                        INSERT INTO pm_share_grants (item_id, recipient_id, sealed_key, created_at)
                        VALUES (%s, %s, %s, NOW())
                        """,
                        (item_id, int(recipient_id), sealed_key_bytes)
                    )
                    grants_created += 1
                except Exception:
                    logger.warning(f"[SHARE_CREATE] Failed to create grant for recipient {recipient_id}")

            conn.commit()

            logger.info(f"[SHARE_CREATE] User {g.current_uid} shared item {item_id} with {grants_created} recipients ({len(encrypted_bytes)} bytes)")
            return jsonify(success=True, item_id=item_id, grants_created=grants_created), 201

        except Exception:
            logger.exception("[SHARE_CREATE] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @app.route("/api/pm/share/inbox", methods=["GET"])
    @jwt_required
    def share_inbox():
        """List items shared WITH current user"""
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)

            cur.execute(
                """
                SELECT i.id AS item_id, i.owner_id, u.username AS owner_username,
                       g.accepted_at, i.created_at, i.expires_at
                FROM pm_share_grants g
                JOIN pm_shared_items i ON i.id = g.item_id
                JOIN pm_users u ON u.uid = i.owner_id
                WHERE g.recipient_id = %s
                  AND (i.expires_at IS NULL OR i.expires_at > UTC_TIMESTAMP())
                ORDER BY i.created_at DESC
                """,
                (g.current_uid,)
            )
            items = cur.fetchall() or []

            for item in items:
                if item.get("created_at"):
                    item["created_at"] = _as_utc(item["created_at"]).isoformat().replace("+00:00", "Z")
                if item.get("accepted_at"):
                    item["accepted_at"] = _as_utc(item["accepted_at"]).isoformat().replace("+00:00", "Z")
                if item.get("expires_at"):
                    item["expires_at"] = _as_utc(item["expires_at"]).isoformat().replace("+00:00", "Z")

            return jsonify(success=True, items=items), 200

        except Exception:
            logger.exception("[SHARE_INBOX] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @app.route("/api/pm/share/outbox", methods=["GET"])
    @jwt_required
    def share_outbox():
        """List items shared BY current user"""
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)

            cur.execute(
                """
                SELECT i.id AS item_id, i.checksum, i.created_at, i.expires_at,
                       COUNT(g.id) AS grant_count,
                       SUM(CASE WHEN g.accepted_at IS NOT NULL THEN 1 ELSE 0 END) AS accepted_count
                FROM pm_shared_items i
                LEFT JOIN pm_share_grants g ON g.item_id = i.id
                WHERE i.owner_id = %s
                GROUP BY i.id
                ORDER BY i.created_at DESC
                """,
                (g.current_uid,)
            )
            items = cur.fetchall() or []

            for item in items:
                item["checksum"] = base64.b64encode(item["checksum"]).decode("utf-8")
                if item.get("created_at"):
                    item["created_at"] = _as_utc(item["created_at"]).isoformat().replace("+00:00", "Z")
                if item.get("expires_at"):
                    item["expires_at"] = _as_utc(item["expires_at"]).isoformat().replace("+00:00", "Z")

            return jsonify(success=True, items=items), 200

        except Exception:
            logger.exception("[SHARE_OUTBOX] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @app.route("/api/pm/share/item/<int:item_id>", methods=["GET"])
    @jwt_required
    def share_get_item(item_id: int):
        """Get shared item (must be owner or recipient)"""
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)

            # Check access
            cur.execute(
                """
                SELECT i.encrypted_data, i.checksum, i.owner_id, u.username AS owner_username,
                       g.sealed_key, g.accepted_at
                FROM pm_shared_items i
                JOIN pm_users u ON u.uid = i.owner_id
                LEFT JOIN pm_share_grants g ON g.item_id = i.id AND g.recipient_id = %s
                WHERE i.id = %s
                  AND (i.owner_id = %s OR g.recipient_id = %s)
                  AND (i.expires_at IS NULL OR i.expires_at > UTC_TIMESTAMP())
                LIMIT 1
                """,
                (g.current_uid, item_id, g.current_uid, g.current_uid)
            )
            item = cur.fetchone()

            if not item:
                return jsonify(success=False, message="Item not found or access denied"), 404

            return jsonify(
                success=True,
                encrypted_data=base64.b64encode(item["encrypted_data"]).decode("utf-8"),
                sealed_key=base64.b64encode(item["sealed_key"]).decode("utf-8") if item.get("sealed_key") else None,
                checksum=base64.b64encode(item["checksum"]).decode("utf-8"),
                owner_username=item["owner_username"],
                is_owner=(item["owner_id"] == g.current_uid),
                accepted_at=_as_utc(item["accepted_at"]).isoformat().replace("+00:00", "Z") if item.get("accepted_at") else None
            ), 200

        except Exception:
            logger.exception("[SHARE_GET_ITEM] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @app.route("/api/pm/share/item/<int:item_id>/accept", methods=["POST"])
    @jwt_required
    def share_accept(item_id: int):
        """Accept shared item"""
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute(
                """
                UPDATE pm_share_grants
                SET accepted_at = NOW()
                WHERE item_id = %s AND recipient_id = %s AND accepted_at IS NULL
                """,
                (item_id, g.current_uid)
            )
            updated = cur.rowcount
            conn.commit()

            if updated == 0:
                return jsonify(success=False, message="Item not found or already accepted"), 404

            logger.info(f"[SHARE_ACCEPT] User {g.current_uid} accepted item {item_id}")
            return jsonify(success=True, message="Item accepted"), 200

        except Exception:
            logger.exception("[SHARE_ACCEPT] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @app.route("/api/pm/share/item/<int:item_id>", methods=["DELETE"])
    @jwt_required
    def share_delete(item_id: int):
        """Delete shared item (owner) or remove grant (recipient)"""
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)

            # Check if owner
            cur.execute(
                """
                SELECT owner_id FROM pm_shared_items
                WHERE id = %s
                LIMIT 1
                """,
                (item_id,)
            )
            item = cur.fetchone()

            if not item:
                return jsonify(success=False, message="Item not found"), 404

            if item["owner_id"] == g.current_uid:
                # Owner: delete entire item
                cur.execute("DELETE FROM pm_shared_items WHERE id = %s", (item_id,))
                conn.commit()
                logger.info(f"[SHARE_DELETE] Owner {g.current_uid} deleted item {item_id}")
                return jsonify(success=True, message="Item deleted"), 200
            else:
                # Recipient: delete only their grant
                cur.execute(
                    """
                    DELETE FROM pm_share_grants
                    WHERE item_id = %s AND recipient_id = %s
                    """,
                    (item_id, g.current_uid)
                )
                deleted = cur.rowcount
                conn.commit()

                if deleted == 0:
                    return jsonify(success=False, message="Grant not found"), 404

                logger.info(f"[SHARE_DELETE] Recipient {g.current_uid} removed grant for item {item_id}")
                return jsonify(success=True, message="Grant removed"), 200

        except Exception:
            logger.exception("[SHARE_DELETE] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @app.route("/api/pm/share/item/<int:item_id>/grant/<int:recipient_id>", methods=["DELETE"])
    @jwt_required
    def share_revoke_grant(item_id: int, recipient_id: int):
        """Revoke specific recipient's access (owner only)"""
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)

            # Verify ownership
            cur.execute(
                """
                SELECT owner_id FROM pm_shared_items
                WHERE id = %s
                LIMIT 1
                """,
                (item_id,)
            )
            item = cur.fetchone()

            if not item:
                return jsonify(success=False, message="Item not found"), 404

            if item["owner_id"] != g.current_uid:
                return jsonify(success=False, message="Only owner can revoke grants"), 403

            # Delete grant
            cur.execute(
                """
                DELETE FROM pm_share_grants
                WHERE item_id = %s AND recipient_id = %s
                """,
                (item_id, recipient_id)
            )
            deleted = cur.rowcount
            conn.commit()

            if deleted == 0:
                return jsonify(success=False, message="Grant not found"), 404

            logger.info(f"[SHARE_REVOKE] Owner {g.current_uid} revoked grant for user {recipient_id} on item {item_id}")
            return jsonify(success=True, message="Grant revoked"), 200

        except Exception:
            logger.exception("[SHARE_REVOKE] Error")
            return jsonify(success=False, message="Server error"), 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
