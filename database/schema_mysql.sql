-- SecureRotate MySQL 8.x schema (application database ONLY)
-- Monitored engines (MySQL/Oracle/PostgreSQL/...) are credential metadata, not this DB.

CREATE TABLE IF NOT EXISTS app_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'user',
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_users_role (role),
    INDEX idx_users_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    database_name VARCHAR(128) NOT NULL COMMENT 'Monitored engine: MySQL, Oracle, PostgreSQL, etc.',
    username VARCHAR(255) NOT NULL,
    owner VARCHAR(255) NOT NULL,
    expiry_date DATE NOT NULL,
    status VARCHAR(64) NOT NULL DEFAULT 'Active',
    secret_ref VARCHAR(512) NOT NULL COMMENT 'Vault-style reference only - never store plaintext passwords',
    password_hash VARCHAR(255) NOT NULL COMMENT 'PBKDF2 hash of rotated secret',
    password_salt VARCHAR(128) NOT NULL,
    last_rotated_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    uses_mfa TINYINT NOT NULL DEFAULT 0,
    is_privileged TINYINT NOT NULL DEFAULT 0,
    is_production TINYINT NOT NULL DEFAULT 0,
    INDEX idx_cred_expiry (expiry_date),
    INDEX idx_cred_status (status),
    INDEX idx_cred_engine (database_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    credential_id INT NOT NULL,
    recipients TEXT NOT NULL,
    channel VARCHAR(64) NOT NULL DEFAULT 'email',
    message TEXT NOT NULL,
    status VARCHAR(64) NOT NULL DEFAULT 'Sent',
    threshold_days INT NULL COMMENT 'Which expiry threshold triggered this notification',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at DATETIME NULL,
    INDEX idx_notif_cred (credential_id),
    INDEX idx_notif_status (status),
    CONSTRAINT fk_notif_cred FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rotation_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    credential_id INT NOT NULL,
    requested_by VARCHAR(255) NOT NULL,
    status VARCHAR(64) NOT NULL,
    started_at DATETIME NOT NULL,
    completed_at DATETIME NULL,
    verification_status VARCHAR(64) NOT NULL DEFAULT 'Pending',
    details TEXT NOT NULL,
    INDEX idx_rot_cred (credential_id),
    CONSTRAINT fk_rot_cred FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    actor VARCHAR(255) NOT NULL,
    action VARCHAR(128) NOT NULL,
    entity VARCHAR(64) NOT NULL,
    entity_id INT NOT NULL,
    details TEXT NOT NULL,
    risk_score DECIMAL(6,4) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_created (created_at),
    INDEX idx_audit_action (action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reset_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(128) NOT NULL UNIQUE,
    credential_id INT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    otp_code_hash VARCHAR(255) NULL COMMENT 'Hashed OTP - never store plaintext OTP',
    otp_attempts INT NOT NULL DEFAULT 0,
    otp_verified TINYINT NOT NULL DEFAULT 0,
    used TINYINT NOT NULL DEFAULT 0,
    expires_at DATETIME NOT NULL,
    INDEX idx_token (token),
    CONSTRAINT fk_reset_cred FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ml_predictions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    credential_id INT NOT NULL,
    model_version VARCHAR(64) NOT NULL,
    risk_probability DECIMAL(8,6) NOT NULL,
    risk_score INT NOT NULL,
    risk_level VARCHAR(32) NOT NULL,
    top_factors JSON NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_pred_cred (credential_id),
    CONSTRAINT fk_pred_cred FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
