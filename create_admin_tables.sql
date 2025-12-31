-- Admin Panel Tables
-- Run this SQL on your database to create the admin audit and notes tables

-- Admin Audit Log - Tracks all admin actions
CREATE TABLE IF NOT EXISTS pm_admin_audit (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    admin_uid BIGINT UNSIGNED NOT NULL,
    action VARCHAR(100) NOT NULL,
    target_user_id BIGINT UNSIGNED,
    details TEXT,
    ip_address VARCHAR(45),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_admin_uid (admin_uid),
    INDEX idx_target_user_id (target_user_id),
    INDEX idx_action (action),
    INDEX idx_created_at (created_at),
    FOREIGN KEY (admin_uid) REFERENCES pm_users(uid) ON DELETE CASCADE,
    FOREIGN KEY (target_user_id) REFERENCES pm_users(uid) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Admin Notes - Notes that admins can add to user accounts
CREATE TABLE IF NOT EXISTS pm_admin_notes (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    admin_uid BIGINT UNSIGNED NOT NULL,
    note TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id),
    INDEX idx_admin_uid (admin_uid),
    INDEX idx_created_at (created_at),
    FOREIGN KEY (user_id) REFERENCES pm_users(uid) ON DELETE CASCADE,
    FOREIGN KEY (admin_uid) REFERENCES pm_users(uid) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Verify tables were created
SELECT 'Admin tables created successfully!' AS status;
SHOW TABLES LIKE 'pm_admin%';
