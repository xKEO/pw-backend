# Deployment Checklist

## Changes Made

### 1. Fixed Registration Bug
- **File:** `pwapp.py` line 450
- **Fix:** Changed `password` column to `password_hash`
- **Impact:** Registration now works properly

### 2. Added Admin Control Panel Routes
- **File:** `admin_routes.py` (new)
- **File:** `pwapp.py` - registered admin blueprint
- **Endpoints Added:**
  - POST `/api/admin/auth/login` - Admin login
  - POST `/api/admin/auth/logout` - Admin logout
  - GET `/api/admin/auth/verify` - Verify session
  - GET `/api/admin/stats/overview` - Dashboard statistics
  - GET `/api/admin/users` - List users with filters
  - GET `/api/admin/users/<uid>` - User details
  - POST `/api/admin/users/<uid>/activate` - Activate user
  - POST `/api/admin/users/<uid>/suspend` - Suspend user
  - GET `/api/admin/health` - System health

### 3. Updated Dependencies
- Added `SQLAlchemy==2.0.25`
- Added `PyMySQL==1.1.0`

## Deployment Steps

### Step 1: Install New Dependencies

```bash
cd /path/to/pw-backend
pip install -r Requirements.txt
```

### Step 2: Restart Flask Server

If using systemd:
```bash
sudo systemctl restart your-flask-service
```

If running manually:
```bash
pkill -f pwapp.py
python3 pwapp.py
```

If using Gunicorn:
```bash
pkill gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 pwapp:app
```

### Step 3: Create First Admin User

**Option A: Using Python Script**
```bash
python create_admin_user.py
```

**Option B: Using SQL**
```sql
-- First register a user through the website, then:
UPDATE pm_users SET is_admin = 1 WHERE username = 'your_username';

-- Or create directly:
INSERT INTO pm_users (username, email, password_hash, is_active, is_verified, is_admin, created_at)
VALUES ('admin', 'admin@example.com', 'YOUR_BCRYPT_HASH', 1, 1, 1, NOW());
```

**Option C: Generate bcrypt hash**
```bash
python -c "import bcrypt; print(bcrypt.hashpw(b'YourPassword123', bcrypt.gensalt()).decode())"
```

### Step 4: Test

1. **Test Registration:**
   - Go to https://passwordmanager.tech
   - Try to register a new account
   - Should work without "Service unavailable" error

2. **Test Admin Login:**
   - Go to https://passwordmanager.tech/admin/login
   - Login with admin credentials
   - Should see admin dashboard

## Frontend

The frontend at `A:\web pages\password-manager-site` is ready to deploy. It includes:
- User routes: `/`, `/dashboard`, `/settings/*`
- Admin routes: `/admin/login`, `/admin/dashboard`, `/admin/users`, `/admin/health`

Build command:
```bash
cd "A:\web pages\password-manager-site"
npm run build
```

Upload the `dist/` folder contents to your hosting.

## Notes

- Admin panel uses separate localStorage token (not httpOnly cookies)
- Admin sessions expire after 8 hours
- All admin actions are logged in `pm_admin_audit` table
