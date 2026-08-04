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

-- Alerts

CREATE TABLE IF NOT EXISTS notification_channels (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    type ENUM('telegram', 'webhook') NOT NULL,
    config MEDIUMTEXT NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS alert_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128),
    tenant VARCHAR(64) NULL,
    event_type VARCHAR(64) NOT NULL,
    min_count INT NOT NULL DEFAULT 1,
    cooldown_sec INT NOT NULL DEFAULT 3600,
    channel_ids TEXT NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS alert_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    triggered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    tenant VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    event_data MEDIUMTEXT NOT NULL,
    matched_rule_id INT NULL,
    notifications_result MEDIUMTEXT,
    INDEX (tenant, triggered_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Edge device monitoring

CREATE TABLE IF NOT EXISTS edge_devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    ip VARCHAR(64) NOT NULL,
    check_port INT NULL,
    interval_sec INT NOT NULL DEFAULT 900,
    channel_ids TEXT NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 0,
    source VARCHAR(16) NOT NULL DEFAULT 'auto',
    source_device_id INT NULL,
    source_device_name VARCHAR(128) NULL,
    source_iface VARCHAR(64) NULL,
    last_seen_from_agent DATETIME NULL,
    last_check DATETIME NULL,
    last_status ENUM('unknown','online','offline') NOT NULL DEFAULT 'unknown',
    last_state_change DATETIME NULL,
    consecutive_fails INT NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_tenant_ip (tenant, ip),
    INDEX (tenant), INDEX (enabled, last_check)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS edge_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    edge_id INT NOT NULL,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type ENUM('offline','online') NOT NULL,
    duration_sec INT NULL,
    notifications_result MEDIUMTEXT,
    INDEX (edge_id, ts DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
