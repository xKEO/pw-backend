# Deploy Fixed Backend to VPS

## Files That Need to Be Uploaded

These files have been fixed and need to be uploaded to your VPS:

```
A:\web backends\pw-backend\pwapp.py              (FIXED - password_hash)
A:\web backends\pw-backend\admin_routes.py       (NEW - admin panel endpoints)
A:\web backends\pw-backend\create_admin_user.py  (NEW - admin user creator)
A:\web backends\pw-backend\Requirements.txt      (UPDATED - new dependencies)
```

## Step-by-Step Deployment

### Step 1: Upload Files to VPS

**Option A: Using Git (Recommended)**
```bash
# On your local machine
cd "A:\web backends\pw-backend"
git add .
git commit -m "Fix registration bug and add admin panel"
git push

# On VPS
ssh user@your-vps-ip
cd /path/to/pw-backend
git pull
```

**Option B: Using SCP (Manual)**
```bash
# From Windows (use Git Bash or PowerShell)
scp "A:\web backends\pw-backend\pwapp.py" user@vps-ip:/path/to/backend/
scp "A:\web backends\pw-backend\admin_routes.py" user@vps-ip:/path/to/backend/
scp "A:\web backends\pw-backend\create_admin_user.py" user@vps-ip:/path/to/backend/
scp "A:\web backends\pw-backend\Requirements.txt" user@vps-ip:/path/to/backend/
```

**Option C: Using FileZilla/WinSCP**
1. Connect to your VPS via SFTP
2. Navigate to backend directory
3. Upload these 4 files
4. Overwrite existing files

### Step 2: SSH Into VPS

```bash
ssh user@your-vps-ip
```

### Step 3: Install New Dependencies

```bash
cd /path/to/pw-backend

# Install new packages (SQLAlchemy and PyMySQL)
pip3 install -r Requirements.txt

# Or install them individually
pip3 install SQLAlchemy PyMySQL
```

### Step 4: Restart Backend Service

**If using systemd:**
```bash
# Check service name
sudo systemctl list-units | grep -i flask
# or
sudo systemctl list-units | grep -i password

# Restart the service
sudo systemctl restart passwordmanager
# or whatever your service is called

# Check status
sudo systemctl status passwordmanager
```

**If using Gunicorn manually:**
```bash
# Find and kill existing process
ps aux | grep pwapp
pkill -f pwapp.py

# Start new instance
cd /path/to/pw-backend
gunicorn -w 4 -b 0.0.0.0:5000 pwapp:app --daemon

# Verify it's running
ps aux | grep gunicorn
curl http://localhost:5000/api/health
```

**If using screen/tmux:**
```bash
# Reattach to screen
screen -r flask
# or
tmux attach -t flask

# Press Ctrl+C to stop
# Then start again
python3 pwapp.py

# Detach with Ctrl+A, D (screen) or Ctrl+B, D (tmux)
```

### Step 5: Verify Backend is Running

```bash
# Test health endpoint
curl https://api.passwordmanager.tech/api/health

# Should return:
# {"success":true}
```

### Step 6: Test Registration

```bash
# Test registration endpoint
curl -X POST https://api.passwordmanager.tech/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "Test123!",
    "password2": "Test123!"
  }'

# Should return:
# {"success":true,"message":"Account created successfully","uid":...}
```

## What Changed

### pwapp.py Line 450
```python
# BEFORE (BROKEN):
INSERT INTO pm_users (username, email, password, ...)

# AFTER (FIXED):
INSERT INTO pm_users (username, email, password_hash, ...)
```

### pwapp.py Bottom (NEW)
```python
# Added admin routes
from admin_routes import admin_bp
app.register_blueprint(admin_bp)
```

## Troubleshooting

### Backend won't start
```bash
# Check Python errors
tail -f /var/log/your-service.log

# Test manually
cd /path/to/pw-backend
python3 pwapp.py
# Look for errors in output
```

### ModuleNotFoundError: SQLAlchemy
```bash
# Install missing packages
pip3 install SQLAlchemy PyMySQL
```

### Port 5000 already in use
```bash
# Find what's using port 5000
sudo lsof -i :5000

# Kill the process
sudo kill -9 PID
```

### Registration still fails
```bash
# Check backend logs
tail -f /var/log/flask/error.log

# Verify database connection
python3 -c "
import mysql.connector, os
from dotenv import load_dotenv
load_dotenv()
conn = mysql.connector.connect(
    host=os.getenv('DB_HOST'),
    user=os.getenv('DB_USER'),
    password=os.getenv('DB_PASSWORD'),
    database=os.getenv('DB_NAME')
)
print('Connected!')
conn.close()
"
```

## After Deployment

Once backend is deployed and running:

1. **Test registration** at https://passwordmanager.tech
2. **Create admin user** using `python3 create_admin_user.py`
3. **Test admin panel** at https://passwordmanager.tech/admin/login

## Quick Commands Cheat Sheet

```bash
# Upload files
scp pwapp.py user@vps:/path/to/backend/

# SSH to VPS
ssh user@vps

# Install dependencies
pip3 install -r Requirements.txt

# Restart service
sudo systemctl restart passwordmanager

# Check logs
journalctl -u passwordmanager -f

# Test health
curl https://api.passwordmanager.tech/api/health
```
