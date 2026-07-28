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

function fail(int $code, string $msg): void {
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
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

    // Check for pending commands from the viewer (e.g. "please update")
    $commands = [];
    $state_dir = $config['state_dir'] ?? __DIR__ . '/state';
    $safe = preg_replace('/[^a-zA-Z0-9_-]/', '_', $tenant_header);
    $update_marker = $state_dir . '/update_pending_' . $safe;
    if (is_file($update_marker)) {
        $commands[] = 'update';
        @unlink($update_marker);  // one-shot; delivered = cleared
    }

    http_response_code(200);
    echo json_encode([
        'ok'           => true,
        'tenant'       => $tenant_header,
        'bytes'        => strlen($body),
        'encrypted'    => $encrypted,
        'devices_count' => $devices_count,
        'received_at'  => date('c'),
        'commands'     => $commands,
    ]);
} catch (Throwable $e) {
    error_log('[mm-ingest] ' . $e->getMessage());
    fail(500, 'server error');
}
