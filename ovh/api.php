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
            // Join with latest snapshot per tenant to expose agent commit info
            // (comes from unencrypted envelope metadata — no key needed).
            $stmt = $pdo->query(
                'SELECT t.id, t.first_seen, t.last_seen,
                        TIMESTAMPDIFF(SECOND, t.last_seen, NOW()) AS age_sec,
                        t.last_payload_bytes, t.notes,
                        (SELECT payload FROM snapshots
                         WHERE tenant = t.id
                         ORDER BY received_at DESC LIMIT 1) AS _latest_payload
                 FROM tenants t
                 ORDER BY t.id'
            );
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$r) {
                $r['age_sec'] = $r['age_sec'] !== null ? (int)$r['age_sec'] : null;
                $r['online']  = $r['age_sec'] !== null && $r['age_sec'] < $threshold;
                // Parse public metadata from latest snapshot
                $r['agent_commit'] = null;
                $r['agent_commit_time'] = null;
                if (!empty($r['_latest_payload'])) {
                    $meta = json_decode($r['_latest_payload'], true);
                    if (is_array($meta)) {
                        $r['agent_commit'] = $meta['agent_commit'] ?? null;
                        $r['agent_commit_time'] = $meta['agent_commit_time'] ?? null;
                    }
                }
                unset($r['_latest_payload']);
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

        case 'request_update':
            // Creates a one-shot marker consumed by ingest.php on next heartbeat.
            $tenant = $_GET['tenant'] ?? '';
            if ($tenant === '') {
                http_response_code(400);
                echo json_encode(['error' => 'tenant required']);
                break;
            }
            $state_dir = $config['state_dir'] ?? __DIR__ . '/state';
            if (!is_dir($state_dir)) @mkdir($state_dir, 0700, true);
            $safe = preg_replace('/[^a-zA-Z0-9_-]/', '_', $tenant);
            $marker = $state_dir . '/update_pending_' . $safe;
            file_put_contents($marker, date('c'));
            echo json_encode([
                'ok' => true,
                'tenant' => $tenant,
                'queued_at' => date('c'),
                'note' => 'Delivered on next heartbeat (max 2 min)',
            ]);
            break;

        case 'request_firmware_upgrade':
            // Queue a firmware upgrade on a specific device of a specific tenant.
            // The agent picks it up on next heartbeat and runs firmware.upgrade_device.
            $tenant = $_GET['tenant'] ?? '';
            $device_id = (int)($_GET['device_id'] ?? 0);
            $backup = ($_GET['backup'] ?? 'false') === 'true';
            if ($tenant === '' || $device_id <= 0) {
                http_response_code(400);
                echo json_encode(['error' => 'tenant and device_id required']);
                break;
            }
            $state_dir = $config['state_dir'] ?? __DIR__ . '/state';
            if (!is_dir($state_dir)) @mkdir($state_dir, 0700, true);
            $safe = preg_replace('/[^a-zA-Z0-9_-]/', '_', $tenant);
            $b = $backup ? 'b' : 'n';
            $marker = $state_dir . "/fw_upgrade_{$safe}_{$device_id}_{$b}.pending";
            file_put_contents($marker, date('c'));
            echo json_encode([
                'ok' => true, 'tenant' => $tenant, 'device_id' => $device_id,
                'backup' => $backup, 'queued_at' => date('c'),
                'note' => 'Delivered on next agent heartbeat (max 2 min)',
            ]);
            break;

        case 'pending_firmware_upgrades':
            $state_dir = $config['state_dir'] ?? __DIR__ . '/state';
            $pending = [];
            if (is_dir($state_dir)) {
                foreach (glob($state_dir . '/fw_upgrade_*.pending') as $f) {
                    $base = basename($f, '.pending');
                    // fw_upgrade_TENANT_DEVICEID_[b|n]
                    if (preg_match('/^fw_upgrade_(.+)_(\d+)_([bn])$/', $base, $m)) {
                        $pending[] = [
                            'tenant' => $m[1],
                            'device_id' => (int)$m[2],
                            'backup' => $m[3] === 'b',
                            'queued_at' => date('c', filemtime($f)),
                        ];
                    }
                }
            }
            echo json_encode(['pending' => $pending]);
            break;

        case 'pending_updates':
            // Which tenants have update_pending marker set right now.
            $state_dir = $config['state_dir'] ?? __DIR__ . '/state';
            $pending = [];
            if (is_dir($state_dir)) {
                foreach (glob($state_dir . '/update_pending_*') as $f) {
                    $tenant = substr(basename($f), strlen('update_pending_'));
                    $pending[] = [
                        'tenant'     => $tenant,
                        'queued_at'  => date('c', filemtime($f)),
                    ];
                }
            }
            echo json_encode(['pending' => $pending]);
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
