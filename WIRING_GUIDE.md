# Complete Wiring Guide - Password Manager

This guide shows what needs to be connected for the entire system to work.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Users & Admins                            │
└────────────┬────────────────────────────────┬────────────────┘
             │                                │
             ▼                                ▼
┌────────────────────────┐      ┌────────────────────────────┐
│  Frontend (React/Vite) │      │  Admin Panel (React/Vite)  │
│  passwordmanager.tech  │      │  /admin routes             │
│  - Landing             │      │  - Login                   │
│  - Register/Login      │      │  - Dashboard               │
│  - Dashboard           │      │  - User Management         │
│  - Settings            │      │  - System Health           │
└────────────┬───────────┘      └──────────────┬─────────────┘
             │                                  │
             └──────────────┬───────────────────┘
                            ▼
                ┌───────────────────────┐
                │  Flask Backend API    │
                │  api.passwordmanager  │
                │  .tech:5000           │
                └───────────┬───────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │  MySQL Database       │
                │  (cPanel hosting)     │
                │  hostilit_loyalty     │
                └───────────────────────┘
```

## Checklist: What Needs to be Wired

### ☐ 1. Database Schema

**Location:** MySQL database on cPanel
**Required Tables:**

```sql
-- Check if these tables exist:
SHOW TABLES LIKE 'pm_%';

-- Should return:
pm_users
pm_refresh_tokens
pm_entitlements
pm_stripe_subscriptions
pm_vaults
pm_vault_versions
pm_user_keys
pm_shared_items
pm_share_grants
pm_admin_audit
pm_admin_notes
```

**If missing, run migrations:**
```bash
# In: A:\web backends\pw-backend\migrations\
# Run each .sql file in order:
001_vault_sync_schema.sql
002_sharing_schema.sql
003_admin_tables.sql
```

**Verify `pm_users` has `is_admin` column:**
```sql
DESCRIBE pm_users;
-- Should show: is_admin (tinyint, default 0)
```

### ☐ 2. Backend Environment Variables

**File:** `A:\web backends\pw-backend\.env`
**Required variables:**

```env
# Database Connection
DB_HOST=webhosting2017.is.cc          ✓ Already set
DB_USER=hostilit_ok                    ✓ Already set
DB_PASSWORD=edqm>2X-~(nSP}$V^%P2cvIW@NAC0=  ✓ Already set
DB_NAME=hostilit_loyalty               ✓ Already set

# JWT Authentication
JWT_SECRET=0994134b20e1cff82544db77a9644fa9c9c0c04e3abe59d52cbc4b25f2f60c56  ✓ Already set
JWT_ALGO=HS256                         ✓ Already set
JWT_EXP_MINUTES=60                     ✓ Already set

# CORS - MUST MATCH FRONTEND DOMAIN
ALLOWED_ORIGINS=https://passwordmanager.tech  ✓ Already set

# Stripe (if using billing)
STRIPE_SECRET_KEY=sk_live_xxxx         ⚠️ UPDATE with real key
STRIPE_WEBHOOK_SECRET=whsec_xxxx       ⚠️ UPDATE with real key
STRIPE_PRICE_ID=price_xxxx             ⚠️ UPDATE with real price ID

# Frontend URL
FRONTEND_URL=https://passwordmanager.tech  ✓ Already set
```

**Test database connection:**
```bash
cd "A:\web backends\pw-backend"
python -c "import mysql.connector; import os; from dotenv import load_dotenv; load_dotenv(); conn = mysql.connector.connect(host=os.getenv('DB_HOST'), user=os.getenv('DB_USER'), password=os.getenv('DB_PASSWORD'), database=os.getenv('DB_NAME')); print('✓ Database connected!'); conn.close()"
```

### ☐ 3. Backend Dependencies

**File:** `A:\web backends\pw-backend\Requirements.txt`

**Install on VPS:**
```bash
# SSH into your VPS
ssh user@your-vps-ip

# Navigate to backend folder
cd /path/to/pw-backend

# Install/update dependencies
pip install -r Requirements.txt

# Or with pip3:
pip3 install -r Requirements.txt
```

**Required packages:**
- flask==3.0.0
- flask-cors==4.0.0
- mysql-connector-python==8.2.0
- bcrypt==4.1.2
- pyjwt==2.8.0
- python-dotenv==1.0.0
- stripe==7.8.0
- gunicorn==21.2.0
- **SQLAlchemy==2.0.25** (new)
- **PyMySQL==1.1.0** (new)

### ☐ 4. Backend Deployment

**Upload these files to VPS:**
```bash
# Files that changed:
A:\web backends\pw-backend\pwapp.py              (FIXED + ADMIN ROUTES)
A:\web backends\pw-backend\admin_routes.py       (NEW)
A:\web backends\pw-backend\create_admin_user.py  (NEW)
A:\web backends\pw-backend\Requirements.txt      (UPDATED)
A:\web backends\pw-backend\.env                  (VERIFY)
```

**Start/Restart Flask:**

Option A - If using systemd:
```bash
sudo systemctl restart passwordmanager
```

Option B - If using Gunicorn:
```bash
pkill gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 pwapp:app --daemon
```

Option C - Development mode:
```bash
python3 pwapp.py
```

**Verify backend is running:**
```bash
# Test health endpoint
curl https://api.passwordmanager.tech/api/health

# Should return: {"success": true}
```

### ☐ 5. Create First Admin User

**Method 1: Using script (recommended)**
```bash
# On VPS
cd /path/to/pw-backend
python3 create_admin_user.py

# Enter:
# Username: admin
# Email: admin@yourdomain.com
# Password: (strong password)
```

**Method 2: SQL directly**
```sql
-- First, register a normal user through the website
-- Then make them admin:
UPDATE pm_users SET is_admin = 1 WHERE username = 'yourusername';

-- Verify:
SELECT uid, username, email, is_admin FROM pm_users WHERE is_admin = 1;
```

**Method 3: Create admin from scratch**
```bash
# Generate password hash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'YourPassword123', bcrypt.gensalt()).decode())"

# Copy the hash, then in MySQL:
INSERT INTO pm_users (username, email, password_hash, is_active, is_verified, is_admin, created_at)
VALUES ('admin', 'admin@example.com', 'YOUR_HASH_HERE', 1, 1, 1, NOW());
```

### ☐ 6. Frontend Environment Variables

**File:** `A:\web pages\password-manager-site\.env`

```env
# API Backend URL - MUST MATCH YOUR BACKEND
VITE_API_URL=https://api.passwordmanager.tech

# For local testing, change to:
# VITE_API_URL=http://localhost:5000
```

**Verify this matches your backend domain!**

### ☐ 7. Frontend Build & Deploy

**Build the frontend:**
```bash
cd "A:\web pages\password-manager-site"

# Install dependencies (if needed)
npm install

# Build for production
npm run build

# Output will be in: dist/
```

**Deploy to hosting:**
```bash
# Upload contents of dist/ folder to your web hosting root
# Example structure on hosting:
/public_html/
  ├── index.html
  ├── assets/
  │   ├── index-DtF6WqTv.css
  │   └── index-HCpIaElk.js
  └── (other files)
```

**Configure web server (if using Apache):**
```apache
# .htaccess for React Router
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteBase /
  RewriteRule ^index\.html$ - [L]
  RewriteCond %{REQUEST_FILENAME} !-f
  RewriteCond %{REQUEST_FILENAME} !-d
  RewriteCond %{REQUEST_FILENAME} !-l
  RewriteRule . /index.html [L]
</IfModule>
```

### ☐ 8. CORS Configuration

**Backend must allow frontend domain!**

In `pwapp.py` line 27-28:
```python
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "https://passwordmanager.tech").split(",")
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)
```

**If you have multiple domains:**
```env
# In .env file:
ALLOWED_ORIGINS=https://passwordmanager.tech,https://www.passwordmanager.tech,http://localhost:5173
```

### ☐ 9. DNS Configuration

**Verify DNS records point correctly:**

```
Domain                          Type    Points To
─────────────────────────────────────────────────
passwordmanager.tech           A       Your-Web-Server-IP
www.passwordmanager.tech       A       Your-Web-Server-IP
api.passwordmanager.tech       A       Your-VPS-IP
```

**Test DNS:**
```bash
nslookup passwordmanager.tech
nslookup api.passwordmanager.tech
```

### ☐ 10. SSL Certificates

**Both domains need HTTPS:**
- ✓ `https://passwordmanager.tech` (frontend)
- ✓ `https://api.passwordmanager.tech` (backend)

**If using Let's Encrypt on VPS:**
```bash
certbot --nginx -d api.passwordmanager.tech
```

## Testing Checklist

### Test User Features:

1. **Registration**
   - Go to: `https://passwordmanager.tech`
   - Click "Sign Up"
   - Fill form and submit
   - Should see success message (no "Service unavailable")

2. **Login**
   - Enter credentials
   - Should receive JWT token
   - Should redirect to dashboard or settings

3. **Dashboard** (Premium required)
   - Should show "Upgrade to Premium" if not subscribed

4. **Settings**
   - Account tab: Shows username, email
   - Billing tab: Shows subscription status
   - Help tab: Shows FAQ

### Test Admin Features:

1. **Admin Login**
   - Go to: `https://passwordmanager.tech/admin/login`
   - Enter admin credentials
   - Should redirect to `/admin/dashboard`

2. **Admin Dashboard**
   - Should show: Total users, subscriptions, MRR, vaults
   - Should show user breakdown stats

3. **User Management**
   - Go to: `/admin/users`
   - Should list all users
   - Test search and filters
   - Click "View Details" on a user

4. **User Detail**
   - Should show account info, subscription, vault stats
   - Test "Suspend User" button
   - Test "Activate User" button

5. **System Health**
   - Go to: `/admin/health`
   - Should show API status, database status, error counts

## Common Issues & Solutions

### Issue: "Service unavailable" on registration
**Cause:** Database column mismatch
**Fix:** Already fixed in pwapp.py (password → password_hash)

### Issue: CORS error in browser console
**Cause:** Backend doesn't allow frontend domain
**Fix:** Update ALLOWED_ORIGINS in .env, restart backend

### Issue: Admin login returns 401
**Cause:** User is not marked as admin
**Fix:** Run `UPDATE pm_users SET is_admin = 1 WHERE username = 'youruser';`

### Issue: Admin dashboard shows "Loading..." forever
**Cause:** Backend admin routes not registered
**Fix:** Verify `app.register_blueprint(admin_bp)` is in pwapp.py, restart

### Issue: Frontend shows "Failed to fetch"
**Cause:** Backend not running or wrong API URL
**Fix:**
1. Check backend is running: `curl https://api.passwordmanager.tech/api/health`
2. Verify VITE_API_URL in frontend .env
3. Rebuild frontend: `npm run build`

## Connection Flow Diagram

### User Registration Flow:
```
User Form → Frontend → POST /api/auth/register → Backend → Database
                                                     ↓
                                               Create user with
                                               password_hash
                                                     ↓
Frontend ← Success ← Backend ← Database confirmation
```

### Admin Login Flow:
```
Admin Form → Frontend → POST /api/admin/auth/login → Backend
                                                         ↓
                                              Check is_admin=1
                                              Verify bcrypt hash
                                                         ↓
                                              Create session token
                                              Store in memory
                                                         ↓
Frontend ← Token + Admin Data ← Backend ← Session created
    ↓
Store token in localStorage
Redirect to /admin/dashboard
```

### Admin Dashboard Data Flow:
```
Frontend → GET /api/admin/stats/overview → Backend
                                              ↓
                                    Verify admin session token
                                              ↓
                                    Query database for:
                                    - Count users
                                    - Count subscriptions
                                    - Calculate MRR
                                    - Count vaults
                                              ↓
Frontend ← JSON Stats ← Backend ← Database results
    ↓
Render dashboard cards
```

## Quick Start Commands

### Deploy Everything:

```bash
# 1. Backend (on VPS)
ssh user@vps-ip
cd /path/to/pw-backend
git pull  # or upload files manually
pip3 install -r Requirements.txt
gunicorn -w 4 -b 0.0.0.0:5000 pwapp:app --daemon

# 2. Create admin user
python3 create_admin_user.py

# 3. Frontend (local, then upload)
cd "A:\web pages\password-manager-site"
npm run build
# Upload dist/ to hosting

# 4. Test
# Open: https://passwordmanager.tech
# Test registration
# Open: https://passwordmanager.tech/admin/login
# Test admin login
```

## Support

If something doesn't work:
1. Check browser console for errors
2. Check backend logs for errors
3. Verify database connection
4. Verify CORS settings
5. Verify DNS resolves correctly
6. Verify SSL certificates are valid
