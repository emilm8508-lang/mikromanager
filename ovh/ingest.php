<?php
/**
 * MikroManager central — ingest endpoint.
 *
 * Security layers (in order):
 *   1. HTTPS only (.htaccess redirect)
 *   2. POST method required
 *   3. Rate limit per source IP (config: rate_limit_per_min)
 *   4. Tenant ID from header must exist in config
 *   5. Source IP must match tenant's allow_ips (if configured)
 *   6. HMAC-SHA256(api_key, timestamp || "|" || body) signature verified
 *      (timing-safe), with timestamp window check (±300s default)
 *   7. Body stored as-is — may be plaintext JSON OR an E2E-encrypted envelope
 *
 * Server NEVER sees the plaintext snapshot when E2E encryption is active.
 */

declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

$config = require __DIR__ . '/config.php';
require_once __DIR__ . '/notifications.php';

function fail(int $code, string $msg): void {
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

// Deterministic string form of the commands list, used to HMAC-sign the
// response so the agent can verify commands weren't injected/tampered with
// downstream of this script. Must match services/uplink.py's
// _canonical_commands() exactly, token for token.
function canonical_commands(array $commands): string {
    $parts = [];
    foreach ($commands as $c) {
        if (is_string($c)) {
            $parts[] = $c;
        } elseif (is_array($c) && ($c['type'] ?? '') === 'firmware_upgrade') {
            $parts[] = 'firmware_upgrade:' . (int)($c['device_id'] ?? 0) . ':' . (!empty($c['backup']) ? '1' : '0');
        } elseif (is_array($c) && ($c['type'] ?? '') === 'fetch_logs') {
            $parts[] = 'fetch_logs:' . (int)($c['device_id'] ?? 0) . ':' . (int)($c['limit'] ?? 0);
        } elseif (is_array($c) && ($c['type'] ?? '') === 'linux_apt_upgrade') {
            $parts[] = 'linux_apt_upgrade:' . (int)($c['host_id'] ?? 0);
        } elseif (is_array($c) && ($c['type'] ?? '') === 'windows_update') {
            // Deliberately NOT including reason in the signed string —
            // free-text in a signature is fragile across encodings, and
            // the fact "someone with the right key queued host_id N" is
            // already what matters for authenticity, same reasoning as
            // linux_apt_upgrade above.
            $parts[] = 'windows_update:' . (int)($c['host_id'] ?? 0);
        } elseif (is_array($c) && ($c['type'] ?? '') === 'windows_restart') {
            $parts[] = 'windows_restart:' . (int)($c['host_id'] ?? 0);
        } elseif (is_array($c) && ($c['type'] ?? '') === 'windows_manage_toggle') {
            $parts[] = 'windows_manage_toggle:' . (!empty($c['enabled']) ? '1' : '0');
        } elseif (is_array($c) && ($c['type'] ?? '') === 'dell_check') {
            $parts[] = 'dell_check:' . (int)($c['server_id'] ?? 0);
        } else {
            $parts[] = 'unknown';
        }
    }
    return implode(',', $parts);
}

// ── Method check ─────────────────────────────────────────────────────────────
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    fail(405, 'POST required');
}

// ── Source IP detection ──────────────────────────────────────────────────────
function client_ip(): string {
    // Trust X-Forwarded-For only if behind known proxy; on OVH shared hosting
    // REMOTE_ADDR is normally the real client IP.
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

$ip = client_ip();

// ── Rate limit (simple file-based counter) ───────────────────────────────────
function rate_limit_check(string $ip, array $config): void {
    $dir = $config['state_dir'];
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $bucket = (int)(time() / 60);
    $path = $dir . '/rl_' . preg_replace('/[^a-zA-Z0-9_-]/', '_', $ip) . '_' . $bucket;
    $count = is_file($path) ? (int)file_get_contents($path) : 0;
    $count++;
    @file_put_contents($path, (string)$count, LOCK_EX);
    if ($count > ($config['rate_limit_per_min'] ?? 30)) {
        fail(429, 'rate limit exceeded');
    }
    // Clean old buckets occasionally (1% of requests)
    if (random_int(0, 99) === 0) {
        foreach (glob($dir . '/rl_*') as $f) {
            if (filemtime($f) < time() - 300) @unlink($f);
        }
    }
}
rate_limit_check($ip, $config);

// ── Headers ──────────────────────────────────────────────────────────────────
/**
 * Get HTTP header value, trying multiple locations because Apache + PHP-FPM
 * on shared hosting (incl. OVH) sometimes strips the Authorization header
 * before it reaches PHP. We check (in order):
 *   1. $_SERVER['HTTP_<NAME>']           — standard
 *   2. $_SERVER['REDIRECT_HTTP_<NAME>']  — forwarded by mod_rewrite/.htaccess
 *   3. apache_request_headers() / getallheaders() — last resort
 */
function get_header(string $name): string {
    $upper = strtoupper(str_replace('-', '_', $name));
    foreach (["HTTP_$upper", "REDIRECT_HTTP_$upper"] as $key) {
        if (!empty($_SERVER[$key])) return $_SERVER[$key];
    }
    if (function_exists('apache_request_headers')) {
        $hdrs = apache_request_headers();
        foreach ($hdrs as $k => $v) {
            if (strcasecmp($k, $name) === 0) return $v;
        }
    }
    if (function_exists('getallheaders')) {
        $hdrs = getallheaders();
        foreach ($hdrs as $k => $v) {
            if (strcasecmp($k, $name) === 0) return $v;
        }
    }
    return '';
}

$auth_header   = get_header('Authorization');
$tenant_header = trim(get_header('X-Tenant'));
$ts_header     = get_header('X-Timestamp');
$sig_header    = get_header('X-Signature');
$encrypted     = get_header('X-Encrypted') === '1';

if (!preg_match('/Bearer\s+(.+)/i', $auth_header, $m)) {
    fail(401, 'missing or malformed Authorization header');
}
$provided_key = trim($m[1]);

// ── Tenant lookup ────────────────────────────────────────────────────────────
if ($tenant_header === '' || !isset($config['tenants'][$tenant_header])) {
    fail(401, 'unknown tenant');
}
$tenant_cfg = $config['tenants'][$tenant_header];
$expected_key = $tenant_cfg['api_key'] ?? '';

if (!hash_equals($expected_key, $provided_key)) {
    fail(401, 'invalid api key');
}

// ── IP allowlist ─────────────────────────────────────────────────────────────
function ip_in_cidr(string $ip, string $cidr): bool {
    if (strpos($cidr, '/') === false) return $ip === $cidr;
    [$subnet, $bits] = explode('/', $cidr, 2);
    $bits = (int)$bits;
    $ipL = ip2long($ip);
    $subL = ip2long($subnet);
    if ($ipL === false || $subL === false) return false;
    $mask = $bits === 0 ? 0 : -1 << (32 - $bits);
    return ($ipL & $mask) === ($subL & $mask);
}

$allowed_ips = $tenant_cfg['allow_ips'] ?? ['0.0.0.0/0'];
$ip_ok = false;
foreach ($allowed_ips as $cidr) {
    if (ip_in_cidr($ip, $cidr)) { $ip_ok = true; break; }
}
if (!$ip_ok) {
    fail(403, 'source IP not in tenant allowlist');
}

// ── Body ─────────────────────────────────────────────────────────────────────
$body = file_get_contents('php://input');
if ($body === false || strlen($body) === 0) {
    fail(400, 'empty body');
}
if (strlen($body) > 2 * 1024 * 1024) {
    fail(413, 'payload too large');
}

// ── Timestamp ────────────────────────────────────────────────────────────────
$ts = (int)$ts_header;
if ($ts <= 0) fail(400, 'missing X-Timestamp');
$now = time();
$window = (int)($config['timestamp_window_sec'] ?? 300);
if (abs($now - $ts) > $window) {
    fail(401, 'timestamp out of window (clock drift or replay?)');
}

// ── HMAC verification ────────────────────────────────────────────────────────
$expected_sig = hash_hmac('sha256', $ts_header . '|' . $body, $expected_key);
if (!hash_equals($expected_sig, $sig_header)) {
    fail(401, 'invalid signature (tampered or wrong key)');
}

// ── Persist ──────────────────────────────────────────────────────────────────
try {
    $dsn = sprintf(
        'mysql:host=%s;dbname=%s;charset=utf8mb4',
        $config['db']['host'],
        $config['db']['name']
    );
    $pdo = new PDO($dsn, $config['db']['user'], $config['db']['password'], [
        PDO::ATTR_ERRMODE          => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);

    // Decode just enough to extract public metadata (not snapshot contents).
    // For E2E envelopes only public fields tenant/sent_at/devices_count are exposed.
    $public_meta = json_decode($body, true);
    $devices_count = is_array($public_meta) ? ($public_meta['devices_count'] ?? null) : null;

    $stmt = $pdo->prepare(
        'INSERT INTO snapshots (tenant, received_at, payload, encrypted)
         VALUES (?, NOW(), ?, ?)'
    );
    $stmt->execute([$tenant_header, $body, $encrypted ? 1 : 0]);

    $stmt = $pdo->prepare(
        'INSERT INTO tenants (id, first_seen, last_seen, last_payload_bytes)
         VALUES (?, NOW(), NOW(), ?)
         ON DUPLICATE KEY UPDATE last_seen = NOW(), last_payload_bytes = VALUES(last_payload_bytes)'
    );
    $stmt->execute([$tenant_header, strlen($body)]);

    // Per-tenant prune: keep only N most recent snapshots
    $max_per_tenant = (int)($config['max_snapshots_per_tenant'] ?? 50);
    $stmt = $pdo->prepare(
        'DELETE FROM snapshots
         WHERE tenant = ?
           AND id NOT IN (
             SELECT id FROM (
               SELECT id FROM snapshots WHERE tenant = ? ORDER BY received_at DESC LIMIT ' . $max_per_tenant . '
             ) t
           )'
    );
    $stmt->execute([$tenant_header, $tenant_header]);

    // Global size cap: if total payload size exceeds limit, delete oldest
    // snapshots across all tenants until under the limit.
    $cap_mb = (float)($config['max_total_snapshot_mb'] ?? 800);
    if ($cap_mb > 0) {
        $cap_bytes = (int)($cap_mb * 1024 * 1024);

        $total = (int)$pdo->query('SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM snapshots')->fetchColumn();

        if ($total > $cap_bytes) {
            // Delete in batches of 50 oldest until under cap (max 10 batches = 500
            // deletes per request, prevents this single insert from blocking too long).
            $batches = 0;
            while ($total > $cap_bytes && $batches < 10) {
                $del = $pdo->prepare(
                    'DELETE FROM snapshots
                     WHERE id IN (
                       SELECT id FROM (
                         SELECT id FROM snapshots ORDER BY received_at ASC LIMIT 50
                       ) t
                     )'
                );
                $del->execute();
                if ($del->rowCount() === 0) break;
                $total = (int)$pdo->query('SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM snapshots')->fetchColumn();
                $batches++;
            }
        }
    }

    // Alerts + edge processing (from unencrypted metadata)
    try {
        $ae = is_array($public_meta) ? ($public_meta['alert_events'] ?? null) : null;
        if (is_array($ae) && !empty($ae)) alerts_process($pdo, $tenant_header, $ae);
    } catch (Throwable $e) { error_log('[mm-alerts] ' . $e->getMessage()); }
    try {
        $ei = is_array($public_meta) ? ($public_meta['edge_ips'] ?? null) : null;
        if (is_array($ei)) edge_sync_from_agent($pdo, $tenant_header, $ei);
    } catch (Throwable $e) { error_log('[mm-edge-sync] ' . $e->getMessage()); }
    try { edge_check_due($pdo, 8); }
    catch (Throwable $e) { error_log('[mm-edge] ' . $e->getMessage()); }

    try {
        $fw = is_array($public_meta) ? ($public_meta['firmware_status'] ?? null) : null;
        firmware_alerts_process($pdo, $tenant_header, is_array($fw) ? $fw : null);
        board_firmware_alerts_process($pdo, $tenant_header, is_array($fw) ? $fw : null);
    } catch (Throwable $e) { error_log('[mm-fw] ' . $e->getMessage()); }

    // Activity log — save agent-reported events + detect agent version changes
    try {
        $ae = is_array($public_meta) ? ($public_meta['activity_events'] ?? null) : null;
        activity_process($pdo, $tenant_header, is_array($ae) ? $ae : null);
    } catch (Throwable $e) { error_log('[mm-activity] ' . $e->getMessage()); }
    try {
        $commit = is_array($public_meta) ? ($public_meta['agent_commit'] ?? null) : null;
        activity_detect_agent_update($pdo, $tenant_header, is_string($commit) ? $commit : null);
    } catch (Throwable $e) { error_log('[mm-agent-upd] ' . $e->getMessage()); }

    // Check for pending commands from the viewer (e.g. "please update")
    // Commands can be strings ("update") or objects with "type" field.
    $commands = [];
    $state_dir = $config['state_dir'] ?? __DIR__ . '/state';
    $safe = preg_replace('/[^a-zA-Z0-9_-]/', '_', $tenant_header);

    // 1. Self-update command
    $update_marker = $state_dir . '/update_pending_' . $safe;
    if (is_file($update_marker)) {
        $commands[] = 'update';
        @unlink($update_marker);
        try {
            $pdo->prepare('INSERT INTO activity_log (tenant, event_type, message, details) VALUES (?, "update_delivered", ?, ?)')
                ->execute([$tenant_header, "Aktualizacja dostarczona do agenta {$tenant_header}", json_encode(['delivered_at'=>date('c')])]);
        } catch (Throwable $e) {}
    }

    // 2. Restart command
    $restart_marker = $state_dir . '/restart_pending_' . $safe;
    if (is_file($restart_marker)) {
        $commands[] = 'restart';
        @unlink($restart_marker);
        try {
            $pdo->prepare('INSERT INTO activity_log (tenant, event_type, message, details) VALUES (?, "restart_delivered", ?, ?)')
                ->execute([$tenant_header, "Restart dostarczony do agenta {$tenant_header}", json_encode(['delivered_at'=>date('c')])]);
        } catch (Throwable $e) {}
    }

    // 2b. Supply-chain scan command (pip-audit/npm audit/Bandit/eslint-security)
    $supplychain_marker = $state_dir . '/supplychain_pending_' . $safe;
    if (is_file($supplychain_marker)) {
        $commands[] = 'supply_chain_scan';
        @unlink($supplychain_marker);
        try {
            $pdo->prepare('INSERT INTO activity_log (tenant, event_type, message, details) VALUES (?, "supply_chain_scan_delivered", ?, ?)')
                ->execute([$tenant_header, "Skan lancucha dostaw dostarczony do agenta {$tenant_header}", json_encode(['delivered_at'=>date('c')])]);
        } catch (Throwable $e) {}
    }

    // 2c. Linux host discovery/refresh scan command
    $linux_scan_marker = $state_dir . '/linux_scan_pending_' . $safe;
    if (is_file($linux_scan_marker)) {
        $commands[] = 'linux_scan';
        @unlink($linux_scan_marker);
        try {
            $pdo->prepare('INSERT INTO activity_log (tenant, event_type, message, details) VALUES (?, "linux_scan_delivered", ?, ?)')
                ->execute([$tenant_header, "Skan hostow Linux dostarczony do agenta {$tenant_header}", json_encode(['delivered_at'=>date('c')])]);
        } catch (Throwable $e) {}
    }

    // 3. Firmware upgrade commands (may be multiple queued for one tenant)
    foreach (glob($state_dir . "/fw_upgrade_{$safe}_*.pending") as $f) {
        $base = basename($f, '.pending');
        if (preg_match('/^fw_upgrade_.+_(\d+)_([bn])$/', $base, $m)) {
            $commands[] = [
                'type' => 'firmware_upgrade',
                'device_id' => (int)$m[1],
                'backup' => $m[2] === 'b',
            ];
            @unlink($f);
        }
    }

    // 3b. Linux apt-upgrade commands (per host, may be multiple queued)
    foreach (glob($state_dir . "/linux_upgrade_{$safe}_*.pending") as $f) {
        $base = basename($f, '.pending');
        if (preg_match('/^linux_upgrade_.+_(\d+)$/', $base, $m)) {
            $commands[] = ['type' => 'linux_apt_upgrade', 'host_id' => (int)$m[1]];
            @unlink($f);
            try {
                $pdo->prepare('INSERT INTO activity_log (tenant, event_type, message, details) VALUES (?, "linux_apt_upgrade_delivered", ?, ?)')
                    ->execute([$tenant_header, "Aktualizacja apt dostarczona do agenta {$tenant_header}", json_encode(['host_id'=>(int)$m[1],'delivered_at'=>date('c')])]);
            } catch (Throwable $e) {}
        }
    }

    // 3c. Windows Update install commands (per host, may be multiple
    // queued) — reason travels as the marker file's own content, since
    // (unlike linux_upgrade's bare timestamp marker) the agent needs it
    // as actual command data, not just a trigger.
    foreach (glob($state_dir . "/win_update_{$safe}_*.pending") as $f) {
        $base = basename($f, '.pending');
        if (preg_match('/^win_update_.+_(\d+)$/', $base, $m)) {
            $reason = trim(@file_get_contents($f));
            $commands[] = ['type' => 'windows_update', 'host_id' => (int)$m[1], 'reason' => $reason];
            @unlink($f);
            try {
                $pdo->prepare('INSERT INTO activity_log (tenant, event_type, message, details) VALUES (?, "windows_update_delivered", ?, ?)')
                    ->execute([$tenant_header, "Aktualizacja Windows dostarczona do agenta {$tenant_header}", json_encode(['host_id'=>(int)$m[1],'reason'=>$reason,'delivered_at'=>date('c')])]);
            } catch (Throwable $e) {}
        }
    }

    // 3d. Windows restart commands (per host, may be multiple queued)
    foreach (glob($state_dir . "/win_restart_{$safe}_*.pending") as $f) {
        $base = basename($f, '.pending');
        if (preg_match('/^win_restart_.+_(\d+)$/', $base, $m)) {
            $reason = trim(@file_get_contents($f));
            $commands[] = ['type' => 'windows_restart', 'host_id' => (int)$m[1], 'reason' => $reason];
            @unlink($f);
            try {
                $pdo->prepare('INSERT INTO activity_log (tenant, event_type, message, details) VALUES (?, "windows_restart_delivered", ?, ?)')
                    ->execute([$tenant_header, "Restart Windows dostarczony do agenta {$tenant_header}", json_encode(['host_id'=>(int)$m[1],'reason'=>$reason,'delivered_at'=>date('c')])]);
            } catch (Throwable $e) {}
        }
    }

    // 3e. Windows-management enable/disable toggle (bare per-tenant flag,
    // not per-host — enabled is encoded in the filename, not content).
    foreach (glob($state_dir . "/win_manage_toggle_{$safe}_*.pending") as $f) {
        $base = basename($f, '.pending');
        if (preg_match('/^win_manage_toggle_.+_([01])$/', $base, $m)) {
            $enabled = $m[1] === '1';
            $commands[] = ['type' => 'windows_manage_toggle', 'enabled' => $enabled];
            @unlink($f);
            try {
                $pdo->prepare('INSERT INTO activity_log (tenant, event_type, message, details) VALUES (?, "windows_manage_toggle_delivered", ?, ?)')
                    ->execute([$tenant_header, "Przelacznik zarzadzania Windows dostarczony do agenta {$tenant_header}", json_encode(['enabled'=>$enabled,'delivered_at'=>date('c')])]);
            } catch (Throwable $e) {}
        }
    }

    // 3f. On-demand Dell iDRAC health re-check (per server, may be multiple
    // queued) — read-only, so unlike the win_update/win_restart markers
    // above there's no MANAGE_ENABLED gate to worry about on the agent side.
    foreach (glob($state_dir . "/dell_check_{$safe}_*.pending") as $f) {
        $base = basename($f, '.pending');
        if (preg_match('/^dell_check_.+_(\d+)$/', $base, $m)) {
            $commands[] = ['type' => 'dell_check', 'server_id' => (int)$m[1]];
            @unlink($f);
            try {
                $pdo->prepare('INSERT INTO activity_log (tenant, event_type, message, details) VALUES (?, "dell_check_delivered", ?, ?)')
                    ->execute([$tenant_header, "Sprawdzenie iDRAC dostarczone do agenta {$tenant_header}", json_encode(['server_id'=>(int)$m[1],'delivered_at'=>date('c')])]);
            } catch (Throwable $e) {}
        }
    }

    // 4. On-demand device log fetch requests (viewer clicked "fetch logs" for
    // a specific device). Result rides along on the agent's NEXT snapshot.
    foreach (glob($state_dir . "/logs_request_{$safe}_*.pending") as $f) {
        $base = basename($f, '.pending');
        if (preg_match('/^logs_request_.+_(\d+)_(\d+)$/', $base, $m)) {
            $commands[] = [
                'type' => 'fetch_logs',
                'device_id' => (int)$m[1],
                'limit' => (int)$m[2],
            ];
            @unlink($f);
        }
    }

    // Sign the commands so the agent can verify they really came from someone
    // holding this tenant's api_key (not just "arrived over this TLS connection").
    // Canonical form is built manually (not json_encode) so PHP and the Python
    // agent are guaranteed to produce byte-identical strings to sign/verify.
    $commands_ts = (string)time();
    $commands_sig = hash_hmac('sha256', $commands_ts . '|' . canonical_commands($commands), $expected_key);

    http_response_code(200);
    echo json_encode([
        'ok'           => true,
        'tenant'       => $tenant_header,
        'bytes'        => strlen($body),
        'encrypted'    => $encrypted,
        'devices_count' => $devices_count,
        'received_at'  => date('c'),
        'commands'     => $commands,
        'commands_ts'  => $commands_ts,
        'commands_sig' => $commands_sig,
    ]);
} catch (Throwable $e) {
    error_log('[mm-ingest] ' . $e->getMessage());
    fail(500, 'server error');
}
