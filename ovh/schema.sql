-- MikroManager central — MySQL schema for OVH shared hosting
-- Execute in phpMyAdmin → SQL tab.

CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(64) PRIMARY KEY,
    last_seen DATETIME,
    first_seen DATETIME,
    last_payload_bytes INT DEFAULT 0,
    notes VARCHAR(255) DEFAULT NULL,
    last_seen_commit VARCHAR(64) NULL  -- for detecting agent updates (v1.7)
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
    last_check_detail VARCHAR(255) NULL,
    -- Set while a cross-tenant verification is in flight (see
    -- edge_verifications below) — blocks a second verification from being
    -- started for the same device, and tells edge_apply_check_result() how
    -- to treat a fresh report while pending (see verify_direction).
    verify_pending TINYINT(1) NOT NULL DEFAULT 0,
    -- 'down' (suspected offline, the original use case) or 'up' (a
    -- self-check optimistically claimed online — NAT-hairpin guard, see
    -- edge_apply_check_result()'s docstring). Only meaningful while
    -- verify_pending=1; mirrors edge_verifications.direction for the
    -- currently-open row so edge_apply_check_result() doesn't need a join
    -- just to decide how to treat the next incoming report.
    verify_direction VARCHAR(8) NULL,
    -- Last time an 'up'-direction verification RESOLVED for this device
    -- (any outcome — confirmed, rejected, or timed out all count as "just
    -- spot-checked"). Used only for devices with check_port IS NULL, where
    -- OVH's own probe can never independently corroborate a self-check at
    -- all (no raw ICMP socket on shared hosting) — throttles how often a
    -- self-reported "online" claim triggers a fresh cross-tenant check to
    -- about once per interval_sec, instead of every single heartbeat.
    last_up_verify_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_tenant_ip (tenant, ip),
    -- Identifies "this WAN interface on this device" independently of its
    -- current IP value, so edge_sync_from_agent() can follow a WAN IP
    -- rotation by updating the row in place (ip = VALUES(ip)) instead of
    -- orphaning the existing monitored/enabled row and silently creating
    -- a brand new disabled one under the old ip-keyed unique constraint
    -- above. NULL source_device_id/source_iface (manual entries) never
    -- collide with each other or with auto rows — MySQL never treats NULL
    -- as equal to NULL in a unique index — so this is a no-op for them.
    UNIQUE KEY uniq_tenant_device_iface (tenant, source_device_id, source_iface),
    INDEX (tenant), INDEX (enabled, last_check)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- Existing install upgrading to this version, run once:
-- ALTER TABLE edge_devices ADD COLUMN last_check_detail VARCHAR(255) NULL;
--
-- Before adding the new unique key below, check for pre-existing duplicate
-- (tenant, source_device_id, source_iface) rows first (a real possibility if
-- you've been running the old ip-keyed version for a while — a WAN IP
-- rotation would have created an orphaned second row under the old logic).
-- ALTER TABLE ADD UNIQUE will fail outright if duplicates exist:
--   SELECT tenant, source_device_id, source_iface, COUNT(*), GROUP_CONCAT(id)
--   FROM edge_devices WHERE source_device_id IS NOT NULL
--   GROUP BY tenant, source_device_id, source_iface HAVING COUNT(*) > 1;
-- For each group found, decide which row to keep (usually the one that's
-- enabled=1 with your real channel/interval settings) and delete the rest,
-- then:
-- ALTER TABLE edge_devices ADD UNIQUE KEY uniq_tenant_device_iface (tenant, source_device_id, source_iface);
-- Existing install upgrading to this version, run once:
-- ALTER TABLE edge_devices ADD COLUMN verify_pending TINYINT(1) NOT NULL DEFAULT 0;
-- ALTER TABLE edge_devices ADD COLUMN verify_direction VARCHAR(8) NULL;
-- ALTER TABLE edge_devices ADD COLUMN last_up_verify_at DATETIME NULL;

-- Cross-tenant edge-device verification (see edge_apply_check_result()/
-- edge_start_verification()/edge_ingest_verify_result() in
-- notifications.php). Before OVH's own active probe or an agent's own
-- self-check is allowed to flip an edge device's status (and fire the
-- Telegram/webhook alert), 1-2 OTHER tenants' agents are asked to
-- independently ping/TCP-check the SAME address as an outside vantage
-- point. Covers two, deliberately asymmetric directions:
--   'down' — about to declare OFFLINE: catches the reporting agent (or
--     OVH's own network) being the thing that's actually unreachable, not
--     the client's WAN. High bar to confirm (all verifiers must fail),
--     low bar to clear (any one success).
--   'up' — a SELF-check (the device's own tenant's agent) optimistically
--     claimed ONLINE: catches NAT-hairpin false positives, where a
--     device's own agent pinging its own public WAN IP from inside its
--     own LAN gets answered even though a real external client can't get
--     through. Low bar to confirm (any one success — genuinely good
--     news), low bar to reject (any one failure — don't trust an
--     unconfirmed self-claim).
-- One row per verification attempt; a device can only have one unresolved
-- row at a time (edge_devices.verify_pending/verify_direction gate that).
CREATE TABLE IF NOT EXISTS edge_verifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    edge_id INT NOT NULL,
    owner_tenant VARCHAR(64) NOT NULL,
    ip VARCHAR(64) NOT NULL,
    check_port INT NULL,
    direction VARCHAR(8) NOT NULL DEFAULT 'down',  -- 'down' | 'up'
    requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    verifier_tenants TEXT NOT NULL,        -- JSON array of tenant slugs asked to check
    -- No DEFAULT here — MySQL rejects a DEFAULT on a TEXT/BLOB column on
    -- older/strict configurations (confirmed on OVH's shared hosting).
    -- Not needed anyway: edge_start_verification()'s INSERT always sets
    -- this explicitly to '[]'.
    results TEXT NOT NULL,                 -- JSON array of {tenant, ok, method, detail, at}
    resolved_at DATETIME NULL,
    -- 'false_positive' | 'confirmed_down' | 'timeout_down' (direction='down')
    -- 'confirmed_up' | 'up_rejected' | 'timeout_up' (direction='up')
    resolution VARCHAR(16) NULL,
    INDEX idx_edge (edge_id),
    INDEX idx_unresolved (resolved_at, requested_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- Existing install upgrading to this version, run once:
-- ALTER TABLE edge_verifications ADD COLUMN direction VARCHAR(8) NOT NULL DEFAULT 'down';

-- Activity log (v1.7) — timeline of interesting events (firmware upgraded,
-- agent restarted after update, backups, etc.). Purely informational, shown
-- on the dashboard. NOT tied to notification channels.

CREATE TABLE IF NOT EXISTS activity_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    tenant VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    message VARCHAR(500) NOT NULL,
    details MEDIUMTEXT NULL,           -- JSON
    INDEX (tenant, ts DESC),
    INDEX (ts DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Add column to tenants for agent_commit change detection.
-- If tenants table already exists, run:
--   ALTER TABLE tenants ADD COLUMN last_seen_commit VARCHAR(64) NULL;

CREATE TABLE IF NOT EXISTS edge_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    edge_id INT NOT NULL,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type ENUM('offline','online') NOT NULL,
    duration_sec INT NULL,
    notifications_result MEDIUMTEXT,
    INDEX (edge_id, ts DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Multi-user accounts (v1.x) — OVH is the primary login source for both
-- individual agents and the "Central" viewer; each agent's local single
-- account remains an emergency fallback for when OVH is unreachable.
-- role/allowed_tenants are orthogonal: role = what a user may DO (admin
-- can write, viewer is read-only), allowed_tenants = WHICH tenants a user
-- may see/act on at all (NULL = all tenants, i.e. a "global" user).

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'viewer',
    allowed_tenants TEXT NULL,          -- JSON array of tenant slugs; NULL = all tenants
    totp_secret VARCHAR(64) NULL,
    totp_enabled TINYINT(1) NOT NULL DEFAULT 0,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login_at DATETIME NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash CHAR(64) NOT NULL,       -- sha256 hex of the bearer token; the raw token is never stored
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    last_seen_at DATETIME NULL,
    ip VARCHAR(64) NULL,
    UNIQUE KEY uniq_token_hash (token_hash),
    INDEX idx_user (user_id),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Agent self-backup (BCP) — encrypted archive of an agent's OWN state
-- (its SQLite DB + Fernet key + session secret + uplink config), distinct
-- from `snapshots` (routine telemetry) and from router config backups
-- (which live entirely on the agent, never uploaded here). `payload` is
-- always E2E ciphertext — OVH stores it opaquely, same trust model as an
-- encrypted snapshot; only someone holding the agent's own enc_key can
-- ever decrypt it. Kept separate from `snapshots` because retention needs
-- to differ (few, large, infrequent backups vs. many small frequent
-- snapshots).
CREATE TABLE IF NOT EXISTS agent_backups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant VARCHAR(64) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    payload MEDIUMTEXT NOT NULL,
    size_bytes INT NOT NULL DEFAULT 0,
    INDEX idx_tenant_time (tenant, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Mikrotik disaster-recovery Word documents (services/drp_docs.py),
-- uploaded the same encrypted-blob way as agent_backups above (see
-- ovh/drp.php) — a separate table/endpoint rather than reusing
-- agent_backups since these are a different kind of artifact (a
-- generated report, not a restorable agent-state snapshot) with their
-- own, much smaller retention count.
CREATE TABLE IF NOT EXISTS drp_documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant VARCHAR(64) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    payload MEDIUMTEXT NOT NULL,
    size_bytes INT NOT NULL DEFAULT 0,
    INDEX idx_tenant_time (tenant, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- AnyDesk-based consultant time tracking (Centrala / global-admin only).
-- Maps a client's AnyDesk client-ID to a tenant, and stores the synced
-- session log pulled from AnyDesk's own REST API (see ovh/anydesk.php) —
-- billable-minutes/category classification happens here, never on AnyDesk's
-- side, so this is the sole source of truth for billing.
CREATE TABLE IF NOT EXISTS anydesk_client_map (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant VARCHAR(64) NOT NULL,
    anydesk_cid VARCHAR(32) NOT NULL,   -- numeric AnyDesk client ID (9 digits)
    label VARCHAR(128) NULL,             -- free-text operator note, e.g. "Router biura"
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_cid (anydesk_cid),
    INDEX idx_tenant (tenant)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS anydesk_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    anydesk_sid VARCHAR(64) NOT NULL,    -- AnyDesk's own session id, dedup key
    tenant VARCHAR(64) NULL,             -- resolved via anydesk_client_map; NULL = unmapped
    from_cid VARCHAR(32) NOT NULL,
    from_alias VARCHAR(255) NULL,
    to_cid VARCHAR(32) NOT NULL,
    to_alias VARCHAR(255) NULL,
    start_time DATETIME NOT NULL,
    end_time DATETIME NULL,              -- NULL while the session is still active
    duration_sec INT NULL,
    billed_minutes INT NULL,             -- GREATEST(15, CEIL(duration_sec/900)*15), set once ended
    active TINYINT(1) NOT NULL DEFAULT 0,
    state VARCHAR(32) NULL,              -- raw AnyDesk state (e.g. 'closed') — only from CSV import; REST-API sync has no equivalent field, stays NULL there
    category VARCHAR(32) NULL,           -- 'billable' | 'training' | 'internal' | NULL = unclassified
    note TEXT NULL,
    classified_by VARCHAR(64) NULL,
    classified_at DATETIME NULL,
    synced_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_sid (anydesk_sid),
    INDEX idx_tenant (tenant),
    INDEX idx_start (start_time),
    INDEX idx_category (category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- Mikrotik upgrade groups defined in Central (agent: services/fleet_schedule.py).
-- The agent of the owning tenant receives all of its tenant's groups with every
-- heartbeat ("fleet_groups_sync" in ingest.php), runs the schedule itself, and
-- reports status back in its normal snapshot. `rev` is bumped on every save so
-- the agent re-applies a group only when it really changed.
CREATE TABLE IF NOT EXISTS fleet_groups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tenant VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    definition TEXT NOT NULL,            -- JSON: device_ids (ordered), channel, schedule_kind, weekday, hour, minute, once_at, enabled, stop_on_failure, backup
    rev INT NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_tenant_name (tenant, name),
    INDEX idx_tenant (tenant)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
