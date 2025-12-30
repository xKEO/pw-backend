"""
Admin Control Panel Routes for Password Manager
Uses SQLAlchemy with remote MySQL database on cPanel hosting
"""

from flask import Blueprint, request, jsonify, g
from sqlalchemy import create_engine, text, func
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, BigInteger, String, Integer, DateTime, Text, LargeBinary, Boolean, TIMESTAMP
from datetime import datetime, timedelta
import os
import secrets
import hashlib
from functools import wraps
import logging

# Create Blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')

# ============================================================
# DATABASE SETUP - Remote MySQL with Connection Pooling
# ============================================================

def get_db_url():
    """Build MySQL connection URL from environment variables"""
    user = os.getenv("DB_USER")
    password = os.getenv("DB_PASSWORD")
    host = os.getenv("DB_HOST")
    database = os.getenv("DB_NAME")
    port = os.getenv("DB_PORT", "3306")

    return f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}"

# Create engine with connection pooling for remote database
engine = create_engine(
    get_db_url(),
    pool_size=5,
    max_overflow=10,
    pool_recycle=3600,  # Recycle connections after 1 hour
    pool_pre_ping=True,  # Verify connection before using
    echo=False  # Set to True for SQL debugging
)

# Create session factory
SessionLocal = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()

# ============================================================
# SQLALCHEMY MODELS (Matching existing schema)
# ============================================================

class User(Base):
    __tablename__ = 'pm_users'

    uid = Column(BigInteger, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class RefreshToken(Base):
    __tablename__ = 'pm_refresh_tokens'

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False)
    token_hash = Column(String(64), unique=True, nullable=False)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime)

class Entitlement(Base):
    __tablename__ = 'pm_entitlements'

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False)
    sku = Column(String(100), default='premium_monthly', nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class StripeSubscription(Base):
    __tablename__ = 'pm_stripe_subscriptions'

    user_id = Column(BigInteger, primary_key=True)
    stripe_customer_id = Column(String(255), unique=True, nullable=False)
    stripe_subscription_id = Column(String(255))
    status = Column(String(50), default='active', nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

class Vault(Base):
    __tablename__ = 'pm_vaults'

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False)
    vault_slug = Column(String(255), nullable=False)
    vault_name = Column(String(255), default='My Vault', nullable=False)
    current_version = Column(Integer, default=1, nullable=False)
    current_checksum = Column(LargeBinary(32), nullable=False)
    blob = Column(LargeBinary, nullable=False)  # LONGBLOB
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    deleted_at = Column(DateTime)

class AdminAudit(Base):
    __tablename__ = 'pm_admin_audit'

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    admin_uid = Column(BigInteger, nullable=False)
    action = Column(String(64), nullable=False)
    target_user_id = Column(BigInteger)
    details = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

# ============================================================
# ADMIN SESSION STORAGE (In-memory for simplicity)
# ============================================================

admin_sessions = {}  # {token: {admin_uid: X, expires_at: datetime}}

def generate_admin_token():
    """Generate a random admin session token"""
    return secrets.token_urlsafe(32)

def cleanup_expired_sessions():
    """Remove expired admin sessions"""
    now = datetime.utcnow()
    expired = [token for token, data in admin_sessions.items() if data['expires_at'] < now]
    for token in expired:
        del admin_sessions[token]

# ============================================================
# ADMIN AUTHENTICATION DECORATOR
# ============================================================

def admin_required(f):
    """Decorator to require valid admin session token"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        cleanup_expired_sessions()

        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify(success=False, message='Missing or invalid Authorization header'), 401

        token = auth_header.split(' ', 1)[1]

        if token not in admin_sessions:
            return jsonify(success=False, message='Invalid or expired session'), 401

        session_data = admin_sessions[token]
        if session_data['expires_at'] < datetime.utcnow():
            del admin_sessions[token]
            return jsonify(success=False, message='Session expired'), 401

        g.admin_uid = session_data['admin_uid']
        g.admin_token = token

        return f(*args, **kwargs)
    return decorated_function

# ============================================================
# ADMIN ROUTES
# ============================================================

@admin_bp.route('/auth/login', methods=['POST'])
def admin_login():
    """Admin login - validates against pm_users with is_admin=1"""
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return jsonify(success=False, message='Username and password required'), 400

    db = SessionLocal()
    try:
        # Find admin user
        user = db.query(User).filter(
            User.username == username,
            User.is_admin == True
        ).first()

        if not user:
            return jsonify(success=False, message='Invalid credentials'), 401

        # Verify password (assuming bcrypt is used)
        import bcrypt
        if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            return jsonify(success=False, message='Invalid credentials'), 401

        if not user.is_active:
            return jsonify(success=False, message='Account disabled'), 403

        # Create admin session
        token = generate_admin_token()
        admin_sessions[token] = {
            'admin_uid': user.uid,
            'username': user.username,
            'expires_at': datetime.utcnow() + timedelta(hours=8)
        }

        # Log admin login
        audit = AdminAudit(
            admin_uid=user.uid,
            action='admin_login',
            details=f'IP: {request.remote_addr}'
        )
        db.add(audit)
        db.commit()

        return jsonify(
            success=True,
            token=token,
            admin={
                'uid': user.uid,
                'username': user.username,
                'email': user.email
            }
        ), 200

    except Exception as e:
        logging.error(f"[ADMIN_LOGIN] Error: {e}")
        return jsonify(success=False, message='Server error'), 500
    finally:
        db.close()

@admin_bp.route('/auth/logout', methods=['POST'])
@admin_required
def admin_logout():
    """Admin logout - invalidate session token"""
    db = SessionLocal()
    try:
        # Log admin logout
        audit = AdminAudit(
            admin_uid=g.admin_uid,
            action='admin_logout'
        )
        db.add(audit)
        db.commit()

        # Remove session
        if g.admin_token in admin_sessions:
            del admin_sessions[g.admin_token]

        return jsonify(success=True, message='Logged out'), 200

    except Exception as e:
        logging.error(f"[ADMIN_LOGOUT] Error: {e}")
        return jsonify(success=False, message='Server error'), 500
    finally:
        db.close()

@admin_bp.route('/auth/verify', methods=['GET'])
@admin_required
def admin_verify():
    """Verify admin session is still valid"""
    return jsonify(success=True, admin_uid=g.admin_uid), 200

# ============================================================
# DASHBOARD STATS
# ============================================================

@admin_bp.route('/stats/overview', methods=['GET'])
@admin_required
def stats_overview():
    """Get dashboard overview statistics"""
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=7)

        # Total users
        total_users = db.query(func.count(User.uid)).scalar()

        # New users today
        new_users_today = db.query(func.count(User.uid)).filter(
            User.created_at >= today_start
        ).scalar()

        # New users this week
        new_users_week = db.query(func.count(User.uid)).filter(
            User.created_at >= week_start
        ).scalar()

        # Active subscriptions breakdown
        total_with_entitlements = db.query(func.count(func.distinct(Entitlement.user_id))).filter(
            Entitlement.active == True
        ).scalar()

        free_users = total_users - total_with_entitlements
        premium_users = total_with_entitlements

        # MRR calculation (assuming $5/month per premium user)
        mrr = premium_users * 5  # TODO: Get actual price from Stripe

        # Total vaults
        total_vaults = db.query(func.count(Vault.id)).filter(
            Vault.deleted_at == None
        ).scalar()

        # Active sessions today
        active_sessions_today = db.query(func.count(RefreshToken.id)).filter(
            RefreshToken.created_at >= today_start,
            RefreshToken.revoked_at == None
        ).scalar()

        return jsonify(
            success=True,
            stats={
                'total_users': total_users or 0,
                'new_users_today': new_users_today or 0,
                'new_users_week': new_users_week or 0,
                'free_users': free_users or 0,
                'premium_users': premium_users or 0,
                'enterprise_users': 0,  # TODO: Add enterprise tier
                'mrr': mrr,
                'total_vaults': total_vaults or 0,
                'active_sessions_today': active_sessions_today or 0
            }
        ), 200

    except Exception as e:
        logging.error(f"[ADMIN_STATS] Error: {e}")
        return jsonify(success=False, message='Server error'), 500
    finally:
        db.close()

# ============================================================
# USER MANAGEMENT
# ============================================================

@admin_bp.route('/users', methods=['GET'])
@admin_required
def list_users():
    """List users with pagination, search, and filters"""
    db = SessionLocal()
    try:
        # Pagination
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 50)), 100)

        # Search
        search = request.args.get('search', '').strip()

        # Filters
        status = request.args.get('status')  # active, inactive, suspended
        subscription = request.args.get('subscription')  # free, premium, enterprise

        # Build query
        query = db.query(User)

        # Apply search
        if search:
            query = query.filter(
                (User.username.like(f'%{search}%')) |
                (User.email.like(f'%{search}%')) |
                (User.uid == int(search) if search.isdigit() else False)
            )

        # Apply status filter
        if status == 'active':
            query = query.filter(User.is_active == True)
        elif status == 'inactive':
            query = query.filter(User.is_active == False)

        # Apply subscription filter
        if subscription == 'premium':
            # Users with active entitlements
            premium_user_ids = db.query(Entitlement.user_id).filter(
                Entitlement.active == True
            ).distinct()
            query = query.filter(User.uid.in_(premium_user_ids))
        elif subscription == 'free':
            # Users without active entitlements
            premium_user_ids = db.query(Entitlement.user_id).filter(
                Entitlement.active == True
            ).distinct()
            query = query.filter(~User.uid.in_(premium_user_ids))

        # Get total count
        total = query.count()

        # Apply pagination
        users = query.order_by(User.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

        # Format users
        users_data = []
        for user in users:
            # Check if user has premium
            has_premium = db.query(Entitlement).filter(
                Entitlement.user_id == user.uid,
                Entitlement.active == True
            ).first() is not None

            users_data.append({
                'uid': user.uid,
                'username': user.username,
                'email': user.email,
                'is_active': user.is_active,
                'is_verified': user.is_verified,
                'is_admin': user.is_admin,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'subscription_type': 'premium' if has_premium else 'free'
            })

        return jsonify(
            success=True,
            users=users_data,
            pagination={
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        ), 200

    except Exception as e:
        logging.error(f"[ADMIN_LIST_USERS] Error: {e}")
        return jsonify(success=False, message='Server error'), 500
    finally:
        db.close()

@admin_bp.route('/users/<int:uid>', methods=['GET'])
@admin_required
def get_user_detail(uid):
    """Get detailed information about a specific user"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.uid == uid).first()

        if not user:
            return jsonify(success=False, message='User not found'), 404

        # Get subscription details
        entitlements = db.query(Entitlement).filter(
            Entitlement.user_id == uid
        ).order_by(Entitlement.created_at.desc()).all()

        stripe_sub = db.query(StripeSubscription).filter(
            StripeSubscription.user_id == uid
        ).first()

        # Get vault stats
        vault_count = db.query(func.count(Vault.id)).filter(
            Vault.user_id == uid,
            Vault.deleted_at == None
        ).scalar()

        # Get recent activity (last 10 sessions)
        recent_sessions = db.query(RefreshToken).filter(
            RefreshToken.user_id == uid
        ).order_by(RefreshToken.created_at.desc()).limit(10).all()

        return jsonify(
            success=True,
            user={
                'uid': user.uid,
                'username': user.username,
                'email': user.email,
                'is_active': user.is_active,
                'is_verified': user.is_verified,
                'is_admin': user.is_admin,
                'created_at': user.created_at.isoformat() if user.created_at else None
            },
            subscription={
                'entitlements': [{
                    'id': e.id,
                    'sku': e.sku,
                    'active': e.active,
                    'expires_at': e.expires_at.isoformat() if e.expires_at else None,
                    'created_at': e.created_at.isoformat() if e.created_at else None
                } for e in entitlements],
                'stripe': {
                    'customer_id': stripe_sub.stripe_customer_id if stripe_sub else None,
                    'subscription_id': stripe_sub.stripe_subscription_id if stripe_sub else None,
                    'status': stripe_sub.status if stripe_sub else None
                } if stripe_sub else None
            },
            vault_stats={
                'vault_count': vault_count or 0
            },
            recent_activity=[{
                'id': s.id,
                'ip_address': s.ip_address,
                'user_agent': s.user_agent,
                'created_at': s.created_at.isoformat() if s.created_at else None,
                'expires_at': s.expires_at.isoformat() if s.expires_at else None,
                'revoked_at': s.revoked_at.isoformat() if s.revoked_at else None
            } for s in recent_sessions]
        ), 200

    except Exception as e:
        logging.error(f"[ADMIN_USER_DETAIL] Error: {e}")
        return jsonify(success=False, message='Server error'), 500
    finally:
        db.close()

@admin_bp.route('/users/<int:uid>/activate', methods=['POST'])
@admin_required
def activate_user(uid):
    """Activate a user account"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.uid == uid).first()

        if not user:
            return jsonify(success=False, message='User not found'), 404

        user.is_active = True

        # Log action
        audit = AdminAudit(
            admin_uid=g.admin_uid,
            action='user_activate',
            target_user_id=uid
        )
        db.add(audit)
        db.commit()

        return jsonify(success=True, message='User activated'), 200

    except Exception as e:
        logging.error(f"[ADMIN_ACTIVATE_USER] Error: {e}")
        db.rollback()
        return jsonify(success=False, message='Server error'), 500
    finally:
        db.close()

@admin_bp.route('/users/<int:uid>/suspend', methods=['POST'])
@admin_required
def suspend_user(uid):
    """Suspend a user account"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.uid == uid).first()

        if not user:
            return jsonify(success=False, message='User not found'), 404

        user.is_active = False

        # Revoke all sessions
        db.query(RefreshToken).filter(
            RefreshToken.user_id == uid,
            RefreshToken.revoked_at == None
        ).update({'revoked_at': datetime.utcnow()})

        # Log action
        audit = AdminAudit(
            admin_uid=g.admin_uid,
            action='user_suspend',
            target_user_id=uid
        )
        db.add(audit)
        db.commit()

        return jsonify(success=True, message='User suspended'), 200

    except Exception as e:
        logging.error(f"[ADMIN_SUSPEND_USER] Error: {e}")
        db.rollback()
        return jsonify(success=False, message='Server error'), 500
    finally:
        db.close()

# ============================================================
# SYSTEM HEALTH
# ============================================================

@admin_bp.route('/health', methods=['GET'])
@admin_required
def system_health():
    """Get system health status"""
    db = SessionLocal()
    try:
        # Test database connection
        db_status = 'connected'
        try:
            db.execute(text('SELECT 1'))
        except Exception as e:
            db_status = 'disconnected'
            logging.error(f"Database health check failed: {e}")

        # API status (if we got here, API is working)
        api_status = 'operational'

        # Get recent error count (errors in last 24 hours)
        # TODO: Implement error logging table
        recent_errors = 0

        # Uptime (simplified - could use process start time)
        uptime_hours = 24  # TODO: Track actual uptime

        return jsonify(
            success=True,
            health={
                'api_status': api_status,
                'database_status': db_status,
                'uptime_hours': uptime_hours,
                'recent_errors': recent_errors
            }
        ), 200

    except Exception as e:
        logging.error(f"[ADMIN_HEALTH] Error: {e}")
        return jsonify(success=False, message='Server error'), 500
    finally:
        db.close()

# ============================================================
# BLUEPRINT REGISTRATION HELPER
# ============================================================

def register_admin_routes(app):
    """Register admin routes blueprint with Flask app"""
    app.register_blueprint(admin_bp)
    logging.info("[ADMIN] Admin routes registered")
