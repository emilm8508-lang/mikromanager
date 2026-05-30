<?php
/**
 * MikroManager central — ingest endpoint.
 *
 * Receives JSON snapshot from an agent. Auth via:
 *   Header: Authorization: Bearer <tenant_api_key>
 *   Header: X-Tenant: <tenant_id>
 *
 * Stores in MySQL. Keeps last 50 snapshots per tenant.
 */

declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

$config = require __DIR__ . '/config.php';

// ── Method check ─────────────────────────────────────────────────────────────
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'POST required']);
    exit;
}

// ── Auth ─────────────────────────────────────────────────────────────────────
$auth_header   = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$tenant_header = trim($_SERVER['HTTP_X_TENANT'] ?? '');

if (!preg_match('/Bearer\s+(.+)/i', $auth_header, $m)) {
    http_response_code(401);
    echo json_encode(['error' => 'missing or malformed Authorization header']);
    exit;
}
$provided_key = trim($m[1]);

if ($tenant_header === '' || !isset($config['tenants'][$tenant_header])) {
    http_response_code(401);
    echo json_encode(['error' => 'unknown tenant']);
    exit;
}

if (!hash_equals($config['tenants'][$tenant_header], $provided_key)) {
    http_response_code(401);
    echo json_encode(['error' => 'invalid api key']);
    exit;
}

// ── Body ─────────────────────────────────────────────────────────────────────
$body = file_get_contents('php://input');
if ($body === false || strlen($body) === 0) {
    http_response_code(400);
    echo json_encode(['error' => 'empty body']);
    exit;
}

if (strlen($body) > 2 * 1024 * 1024) {  // 2 MB cap
    http_response_code(413);
    echo json_encode(['error' => 'payload too large']);
    exit;
}

$decoded = json_decode($body, true);
if ($decoded === null) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid JSON: ' . json_last_error_msg()]);
    exit;
}

// ── Persist ──────────────────────────────────────────────────────────────────
try {
    $dsn = sprintf(
        'mysql:host=%s;dbname=%s;charset=utf8mb4',
        $config['db']['host'],
        $config['db']['name']
    );
    $pdo = new PDO($dsn, $config['db']['user'], $config['db']['password'], [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);

    // 1. Insert snapshot
    $stmt = $pdo->prepare(
        'INSERT INTO snapshots (tenant, received_at, payload) VALUES (?, NOW(), ?)'
    );
    $stmt->execute([$tenant_header, $body]);

    // 2. Upsert tenants (last_seen, first_seen on first insert)
    $stmt = $pdo->prepare(
        'INSERT INTO tenants (id, first_seen, last_seen, last_payload_bytes)
         VALUES (?, NOW(), NOW(), ?)
         ON DUPLICATE KEY UPDATE last_seen = NOW(), last_payload_bytes = VALUES(last_payload_bytes)'
    );
    $stmt->execute([$tenant_header, strlen($body)]);

    // 3. Prune: keep last 50 per tenant
    $stmt = $pdo->prepare(
        'DELETE FROM snapshots
         WHERE tenant = ?
           AND id NOT IN (
             SELECT id FROM (
               SELECT id FROM snapshots WHERE tenant = ? ORDER BY received_at DESC LIMIT 50
             ) t
           )'
    );
    $stmt->execute([$tenant_header, $tenant_header]);

    http_response_code(200);
    echo json_encode([
        'ok'        => true,
        'tenant'    => $tenant_header,
        'bytes'     => strlen($body),
        'devices'   => $decoded['devices_count'] ?? null,
        'received_at' => date('c'),
    ]);
} catch (Throwable $e) {
    error_log('[mm-ingest] ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'server error']);
}
