#!/usr/bin/env python3
"""
Create First Admin User
Run this script to create your first admin user for the Password Manager admin panel.
"""

import bcrypt
import mysql.connector
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

def create_admin_user():
    # Get admin credentials
    print("=== Create Admin User ===\n")
    username = input("Enter admin username: ").strip()
    email = input("Enter admin email: ").strip()
    password = input("Enter admin password: ").strip()

    if not username or not email or not password:
        print("Error: All fields are required")
        return

    # Hash password
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Connect to database
    try:
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME'),
            port=int(os.getenv('DB_PORT', 3306))
        )
        cursor = conn.cursor()

        # Check if username or email already exists
        cursor.execute(
            "SELECT uid, username, email FROM pm_users WHERE username = %s OR email = %s",
            (username, email)
        )
        existing = cursor.fetchone()

        if existing:
            print(f"\nUser already exists: UID={existing[0]}, Username={existing[1]}, Email={existing[2]}")
            make_admin = input("Make this user an admin? (yes/no): ").strip().lower()

            if make_admin == 'yes':
                cursor.execute("UPDATE pm_users SET is_admin = 1 WHERE uid = %s", (existing[0],))
                conn.commit()
                print(f"✓ User {existing[1]} is now an admin!")
            else:
                print("Operation cancelled.")
        else:
            # Create new admin user
            cursor.execute(
                """INSERT INTO pm_users
                   (username, email, password_hash, is_active, is_verified, is_admin, created_at)
                   VALUES (%s, %s, %s, 1, 1, 1, %s)""",
                (username, email, password_hash, datetime.utcnow())
            )
            conn.commit()
            user_id = cursor.lastrowid
            print(f"\n✓ Admin user created successfully!")
            print(f"  UID: {user_id}")
            print(f"  Username: {username}")
            print(f"  Email: {email}")
            print(f"\nYou can now login to the admin panel at /admin/login")

        cursor.close()
        conn.close()

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    create_admin_user()
