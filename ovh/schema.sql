-- MikroManager central — MySQL schema for OVH shared hosting
-- Execute in phpMyAdmin → SQL tab.

CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(64) PRIMARY KEY,
    last_seen DATETIME,
    first_seen DATETIME,
    last_payload_bytes INT DEFAULT 0,
    notes VARCHAR(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS snapshots (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant VARCHAR(64) NOT NULL,
    received_at DATETIME NOT NULL,
    payload MEDIUMTEXT NOT NULL,
    encrypted TINYINT(1) NOT NULL DEFAULT 0,  -- 1 = E2E ciphertext envelope, 0 = plaintext JSON
    INDEX idx_tenant_time (tenant, received_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- If upgrading existing DB, run this once:
-- ALTER TABLE snapshots ADD COLUMN encrypted TINYINT(1) NOT NULL DEFAULT 0;
