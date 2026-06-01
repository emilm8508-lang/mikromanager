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
// Apache + PHP-FPM on shared hosting often strips Authorization. Check fallbacks.
function get_auth_header(): string {
    foreach (['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'] as $k) {
        if (!empty($_SERVER[$k])) return $_SERVER[$k];
    }
    if (function_exists('apache_request_headers')) {
        foreach (apache_request_headers() as $k => $v) {
            if (strcasecmp($k, 'Authorization') === 0) return $v;
        }
    }
    if (function_exists('getallheaders')) {
        foreach (getallheaders() as $k => $v) {
            if (strcasecmp($k, 'Authorization') === 0) return $v;
        }
    }
    return '';
}

$auth_header = get_auth_header();
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

        case 'usage':
            // Total + per-tenant payload size, plus configured cap.
            $stmt = $pdo->query(
                'SELECT
                   COALESCE(SUM(LENGTH(payload)), 0) AS total_bytes,
                   COUNT(*) AS total_count
                 FROM snapshots'
            );
            $tot = $stmt->fetch(PDO::FETCH_ASSOC);

            $stmt = $pdo->query(
                'SELECT tenant,
                        SUM(LENGTH(payload)) AS bytes,
                        COUNT(*) AS count,
                        MIN(received_at) AS oldest,
                        MAX(received_at) AS newest
                 FROM snapshots
                 GROUP BY tenant
                 ORDER BY bytes DESC'
            );
            $per_tenant = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($per_tenant as &$t) {
                $t['bytes'] = (int)$t['bytes'];
                $t['count'] = (int)$t['count'];
            }

            $cap_mb = (float)($config['max_total_snapshot_mb'] ?? 800);
            $total_bytes = (int)$tot['total_bytes'];
            echo json_encode([
                'total_bytes'      => $total_bytes,
                'total_mb'         => round($total_bytes / 1024 / 1024, 2),
                'total_count'      => (int)$tot['total_count'],
                'cap_mb'           => $cap_mb,
                'percent_of_cap'   => $cap_mb > 0 ? round($total_bytes / 1024 / 1024 / $cap_mb * 100, 1) : null,
                'per_tenant_limit' => (int)($config['max_snapshots_per_tenant'] ?? 50),
                'per_tenant'       => $per_tenant,
            ]);
            break;

        case 'cleanup':
            // Manual: keep only N latest per tenant. Optional ?keep=20
            $keep = max(1, (int)($_GET['keep'] ?? 20));
            $deleted = 0;
            $tenants = $pdo->query('SELECT DISTINCT tenant FROM snapshots')->fetchAll(PDO::FETCH_COLUMN);
            foreach ($tenants as $tn) {
                $stmt = $pdo->prepare(
                    'DELETE FROM snapshots
                     WHERE tenant = ?
                       AND id NOT IN (
                         SELECT id FROM (
                           SELECT id FROM snapshots WHERE tenant = ? ORDER BY received_at DESC LIMIT ' . $keep . '
                         ) t
                       )'
                );
                $stmt->execute([$tn, $tn]);
                $deleted += $stmt->rowCount();
            }
            echo json_encode(['deleted' => $deleted, 'kept_per_tenant' => $keep]);
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
