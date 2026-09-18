<?php
/**
 * MikroManager central — Mikrotik DRP (disaster-recovery) document upload
 * endpoint.
 *
 * A separate file from ingest.php on purpose — same reasoning as
 * ovh/backup.php, which this mirrors almost verbatim: ingest.php is the
 * most frequently-hit, most-tested endpoint in this codebase (every
 * agent, every ~2 minutes), so a low-frequency, unrelated upload doesn't
 * risk touching it.
 *
 * Security layers (identical model to backup.php):
 *   1. HTTPS only (.htaccess redirect)
 *   2. POST method required
 *   3. Rate limit per source IP
 *   4. Tenant ID from header must exist in config
 *   5. Source IP must match tenant's allow_ips (if configured)
 *   6. HMAC-SHA256(api_key, timestamp || "|" || body) signature verified
 *   7. Body is ALWAYS an E2E-encrypted envelope — services/drp_docs.py
 *      only uploads at all when an enc_key is configured (falling back to
 *      "generated locally only" otherwise). This server never sees, and
 *      never needs to see, plaintext device configuration.
 */

declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

$config = require __DIR__ . '/config.php';

function drp_fail(int $code, string $msg): void {
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    drp_fail(405, 'POST required');
}

function drp_client_ip(): string {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

$ip = drp_client_ip();

function drp_rate_limit_check(string $ip, array $config): void {
    $dir = $config['state_dir'];
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $bucket = (int)(time() / 60);
    $path = $dir . '/rldrp_' . preg_replace('/[^a-zA-Z0-9_-]/', '_', $ip) . '_' . $bucket;
    $count = is_file($path) ? (int)file_get_contents($path) : 0;
    $count++;
    @file_put_contents($path, (string)$count, LOCK_EX);
    // DRP generation is infrequent (on demand from Central) — same tight
    // limit as backup.php's, not ingest.php's routine-telemetry rate.
    if ($count > 5) {
        drp_fail(429, 'rate limit exceeded');
    }
    if (random_int(0, 99) === 0) {
        foreach (glob($dir . '/rldrp_*') as $f) {
            if (filemtime($f) < time() - 300) @unlink($f);
        }
    }
}
drp_rate_limit_check($ip, $config);

function drp_get_header(string $name): string {
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

$auth_header   = drp_get_header('Authorization');
$tenant_header = trim(drp_get_header('X-Tenant'));
$ts_header     = drp_get_header('X-Timestamp');
$sig_header    = drp_get_header('X-Signature');

if (!preg_match('/Bearer\s+(.+)/i', $auth_header, $m)) {
    drp_fail(401, 'missing or malformed Authorization header');
}
$provided_key = trim($m[1]);

if ($tenant_header === '' || !isset($config['tenants'][$tenant_header])) {
    drp_fail(401, 'unknown tenant');
}
$tenant_cfg = $config['tenants'][$tenant_header];
$expected_key = $tenant_cfg['api_key'] ?? '';

if (!hash_equals($expected_key, $provided_key)) {
    drp_fail(401, 'invalid api key');
}

function drp_ip_in_cidr(string $ip, string $cidr): bool {
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
    if (drp_ip_in_cidr($ip, $cidr)) { $ip_ok = true; break; }
}
if (!$ip_ok) {
    drp_fail(403, 'source IP not in tenant allowlist');
}

$body = file_get_contents('php://input');
if ($body === false || strlen($body) === 0) {
    drp_fail(400, 'empty body');
}
// A DRP document (many devices' full /export text) can be larger than a
// routine telemetry snapshot but is still just text — same generous cap
// as backup.php's.
if (strlen($body) > 20 * 1024 * 1024) {
    drp_fail(413, 'payload too large');
}

$ts = (int)$ts_header;
if ($ts <= 0) drp_fail(400, 'missing X-Timestamp');
$now = time();
$window = (int)($config['timestamp_window_sec'] ?? 300);
if (abs($now - $ts) > $window) {
    drp_fail(401, 'timestamp out of window (clock drift or replay?)');
}

$expected_sig = hash_hmac('sha256', $ts_header . '|' . $body, $expected_key);
if (!hash_equals($expected_sig, $sig_header)) {
    drp_fail(401, 'invalid signature (tampered or wrong key)');
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
        'INSERT INTO drp_documents (tenant, created_at, payload, size_bytes) VALUES (?, NOW(), ?, ?)'
    );
    $stmt->execute([$tenant_header, $body, strlen($body)]);

    // Keep only the most recent N per tenant — tighter than agent_backups'
    // default since these are generated on demand, not a scheduled
    // safety net; there's rarely a reason to keep more than a couple.
    $max_per_tenant = (int)($config['max_drp_documents_per_tenant'] ?? 3);
    $stmt = $pdo->prepare(
        'DELETE FROM drp_documents
         WHERE tenant = ?
           AND id NOT IN (
             SELECT id FROM (
               SELECT id FROM drp_documents WHERE tenant = ? ORDER BY created_at DESC LIMIT ' . $max_per_tenant . '
             ) t
           )'
    );
    $stmt->execute([$tenant_header, $tenant_header]);

    http_response_code(200);
    echo json_encode(['ok' => true, 'tenant' => $tenant_header, 'bytes' => strlen($body), 'received_at' => date('c')]);
} catch (Throwable $e) {
    error_log('[mm-drp] ' . $e->getMessage());
    drp_fail(500, 'server error');
}
