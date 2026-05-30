<?php
/**
 * MikroManager central — viewer API.
 *
 * Auth via:
 *   Authorization: Bearer <viewer_password>
 *
 * Endpoints (selected by ?action=):
 *   ?action=tenants            → list all tenants + online status
 *   ?action=snapshot&tenant=X  → latest snapshot for tenant X
 *   ?action=history&tenant=X   → list of recent received_at timestamps (last 50)
 */

declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Authorization, Content-Type');
header('Access-Control-Allow-Methods: GET, OPTIONS');

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$config = require __DIR__ . '/config.php';

// ── Auth ─────────────────────────────────────────────────────────────────────
$auth_header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (!preg_match('/Bearer\s+(.+)/i', $auth_header, $m)) {
    http_response_code(401);
    echo json_encode(['error' => 'unauthorized']);
    exit;
}
$provided = trim($m[1]);
if (!hash_equals($config['viewer_password'], $provided)) {
    http_response_code(401);
    echo json_encode(['error' => 'invalid password']);
    exit;
}

// ── Routing ──────────────────────────────────────────────────────────────────
$action = $_GET['action'] ?? 'tenants';
$threshold = (int)($config['offline_threshold_sec'] ?? 300);

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

    switch ($action) {

        case 'tenants':
            $stmt = $pdo->query(
                'SELECT id, first_seen, last_seen,
                        TIMESTAMPDIFF(SECOND, last_seen, NOW()) AS age_sec,
                        last_payload_bytes, notes
                 FROM tenants
                 ORDER BY id'
            );
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$r) {
                $r['age_sec'] = $r['age_sec'] !== null ? (int)$r['age_sec'] : null;
                $r['online']  = $r['age_sec'] !== null && $r['age_sec'] < $threshold;
            }
            echo json_encode([
                'tenants'              => $rows,
                'offline_threshold_sec' => $threshold,
                'server_time'          => date('c'),
            ]);
            break;

        case 'snapshot':
            $tenant = $_GET['tenant'] ?? '';
            if ($tenant === '') {
                http_response_code(400);
                echo json_encode(['error' => 'tenant query param required']);
                break;
            }
            $stmt = $pdo->prepare(
                'SELECT payload, received_at,
                        TIMESTAMPDIFF(SECOND, received_at, NOW()) AS age_sec
                 FROM snapshots
                 WHERE tenant = ?
                 ORDER BY received_at DESC
                 LIMIT 1'
            );
            $stmt->execute([$tenant]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$row) {
                echo json_encode(null);
                break;
            }
            $payload = json_decode($row['payload'], true);
            if (!is_array($payload)) $payload = ['_raw' => $row['payload']];
            $payload['received_at'] = $row['received_at'];
            $payload['age_sec']     = (int)$row['age_sec'];
            $payload['online']      = (int)$row['age_sec'] < $threshold;
            echo json_encode($payload);
            break;

        case 'history':
            $tenant = $_GET['tenant'] ?? '';
            if ($tenant === '') {
                http_response_code(400);
                echo json_encode(['error' => 'tenant query param required']);
                break;
            }
            $stmt = $pdo->prepare(
                'SELECT id, received_at, LENGTH(payload) AS bytes
                 FROM snapshots
                 WHERE tenant = ?
                 ORDER BY received_at DESC
                 LIMIT 50'
            );
            $stmt->execute([$tenant]);
            echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
            break;

        default:
            http_response_code(400);
            echo json_encode(['error' => 'unknown action']);
    }
} catch (Throwable $e) {
    error_log('[mm-api] ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'server error']);
}
