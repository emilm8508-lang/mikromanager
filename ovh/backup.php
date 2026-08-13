<?php
/**
 * MikroManager central — agent self-backup upload endpoint.
 *
 * A separate file from ingest.php on purpose: ingest.php is the most
 * frequently-hit, most-tested endpoint in this codebase (every agent, every
 * ~2 minutes) — this duplicates its small tenant/HMAC auth block rather
 * than risk touching that file for a low-frequency, unrelated feature.
 *
 * Security layers (same model as ingest.php):
 *   1. HTTPS only (.htaccess redirect)
 *   2. POST method required
 *   3. Rate limit per source IP
 *   4. Tenant ID from header must exist in config
 *   5. Source IP must match tenant's allow_ips (if configured)
 *   6. HMAC-SHA256(api_key, timestamp || "|" || body) signature verified
 *   7. Body is ALWAYS an E2E-encrypted envelope — the agent refuses to
 *      build a backup at all if no enc_key is configured (see
 *      backend/services/agent_backup.py). This server never sees, and
 *      never needs to see, the plaintext database/keys.
 */

declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

$config = require __DIR__ . '/config.php';

function backup_fail(int $code, string $msg): void {
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    backup_fail(405, 'POST required');
}

function backup_client_ip(): string {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

$ip = backup_client_ip();

function backup_rate_limit_check(string $ip, array $config): void {
    $dir = $config['state_dir'];
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $bucket = (int)(time() / 60);
    $path = $dir . '/rlbackup_' . preg_replace('/[^a-zA-Z0-9_-]/', '_', $ip) . '_' . $bucket;
    $count = is_file($path) ? (int)file_get_contents($path) : 0;
    $count++;
    @file_put_contents($path, (string)$count, LOCK_EX);
    // Backups are infrequent (weekly) — a much tighter limit than ingest.php's
    // routine-telemetry rate is appropriate and doesn't hurt legitimate use.
    if ($count > 5) {
        backup_fail(429, 'rate limit exceeded');
    }
    if (random_int(0, 99) === 0) {
        foreach (glob($dir . '/rlbackup_*') as $f) {
            if (filemtime($f) < time() - 300) @unlink($f);
        }
    }
}
backup_rate_limit_check($ip, $config);

function backup_get_header(string $name): string {
    $upper = strtoupper(str_replace('-', '_', $name));
    foreach (["HTTP_$upper", "REDIRECT_HTTP_$upper"] as $key) {
        if (!empty($_SERVER[$key])) return $_SERVER[$key];
    }
    if (function_exists('apache_request_headers')) {
        foreach (apache_request_headers() as $k => $v) {
            if (strcasecmp($k, $name) === 0) return $v;
        }
    }
    if (function_exists('getallheaders')) {
        foreach (getallheaders() as $k => $v) {
            if (strcasecmp($k, $name) === 0) return $v;
        }
    }
    return '';
}

$auth_header   = backup_get_header('Authorization');
$tenant_header = trim(backup_get_header('X-Tenant'));
$ts_header     = backup_get_header('X-Timestamp');
$sig_header    = backup_get_header('X-Signature');

if (!preg_match('/Bearer\s+(.+)/i', $auth_header, $m)) {
    backup_fail(401, 'missing or malformed Authorization header');
}
$provided_key = trim($m[1]);

if ($tenant_header === '' || !isset($config['tenants'][$tenant_header])) {
    backup_fail(401, 'unknown tenant');
}
$tenant_cfg = $config['tenants'][$tenant_header];
$expected_key = $tenant_cfg['api_key'] ?? '';

if (!hash_equals($expected_key, $provided_key)) {
    backup_fail(401, 'invalid api key');
}

function backup_ip_in_cidr(string $ip, string $cidr): bool {
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
    if (backup_ip_in_cidr($ip, $cidr)) { $ip_ok = true; break; }
}
if (!$ip_ok) {
    backup_fail(403, 'source IP not in tenant allowlist');
}

$body = file_get_contents('php://input');
if ($body === false || strlen($body) === 0) {
    backup_fail(400, 'empty body');
}
// Backups (a whole SQLite DB + keys) are much bigger than a routine
// telemetry snapshot — generous but still bounded cap.
if (strlen($body) > 20 * 1024 * 1024) {
    backup_fail(413, 'payload too large');
}

$ts = (int)$ts_header;
if ($ts <= 0) backup_fail(400, 'missing X-Timestamp');
$now = time();
$window = (int)($config['timestamp_window_sec'] ?? 300);
if (abs($now - $ts) > $window) {
    backup_fail(401, 'timestamp out of window (clock drift or replay?)');
}

$expected_sig = hash_hmac('sha256', $ts_header . '|' . $body, $expected_key);
if (!hash_equals($expected_sig, $sig_header)) {
    backup_fail(401, 'invalid signature (tampered or wrong key)');
}

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

    $stmt = $pdo->prepare(
        'INSERT INTO agent_backups (tenant, created_at, payload, size_bytes) VALUES (?, NOW(), ?, ?)'
    );
    $stmt->execute([$tenant_header, $body, strlen($body)]);

    // Keep only the most recent N backups per tenant — these are much
    // larger than routine snapshots, so retention is intentionally tight.
    $max_per_tenant = (int)($config['max_backups_per_tenant'] ?? 5);
    $stmt = $pdo->prepare(
        'DELETE FROM agent_backups
         WHERE tenant = ?
           AND id NOT IN (
             SELECT id FROM (
               SELECT id FROM agent_backups WHERE tenant = ? ORDER BY created_at DESC LIMIT ' . $max_per_tenant . '
             ) t
           )'
    );
    $stmt->execute([$tenant_header, $tenant_header]);

    http_response_code(200);
    echo json_encode(['ok' => true, 'tenant' => $tenant_header, 'bytes' => strlen($body), 'received_at' => date('c')]);
} catch (Throwable $e) {
    error_log('[mm-backup] ' . $e->getMessage());
    backup_fail(500, 'server error');
}
