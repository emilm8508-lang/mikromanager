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
header('Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS');

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$config = require __DIR__ . '/config.php';
require_once __DIR__ . '/notifications.php';

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
            $tenant = $_GET['tenant'] ?? '';
            if ($tenant === '') { http_response_code(400); echo json_encode(['error'=>'tenant required']); break; }
            $state_dir = $config['state_dir'] ?? __DIR__ . '/state';
            if (!is_dir($state_dir)) @mkdir($state_dir, 0700, true);
            $safe = preg_replace('/[^a-zA-Z0-9_-]/', '_', $tenant);
            file_put_contents($state_dir . '/update_pending_' . $safe, date('c'));
            // Log to activity timeline
            $pdo->prepare('INSERT INTO activity_log (tenant, event_type, message, details) VALUES (?, "update_queued", ?, ?)')
                ->execute([$tenant, "Aktualizacja zakolejkowana dla {$tenant}", json_encode(['queued_at'=>date('c')])]);
            echo json_encode(['ok'=>true,'tenant'=>$tenant,'queued_at'=>date('c'),'note'=>'Delivered on next heartbeat (max 2 min)']);
            break;

        case 'request_restart':
            $tenant = $_GET['tenant'] ?? '';
            if ($tenant === '') { http_response_code(400); echo json_encode(['error'=>'tenant required']); break; }
            $state_dir = $config['state_dir'] ?? __DIR__ . '/state';
            if (!is_dir($state_dir)) @mkdir($state_dir, 0700, true);
            $safe = preg_replace('/[^a-zA-Z0-9_-]/', '_', $tenant);
            file_put_contents($state_dir . '/restart_pending_' . $safe, date('c'));
            $pdo->prepare('INSERT INTO activity_log (tenant, event_type, message, details) VALUES (?, "restart_queued", ?, ?)')
                ->execute([$tenant, "Restart zakolejkowany dla {$tenant}", json_encode(['queued_at'=>date('c')])]);
            echo json_encode(['ok'=>true,'tenant'=>$tenant,'queued_at'=>date('c'),'note'=>'Delivered on next heartbeat (max 2 min)']);
            break;

        case 'pending_restarts':
            $state_dir = $config['state_dir'] ?? __DIR__ . '/state';
            $pending = [];
            if (is_dir($state_dir)) {
                foreach (glob($state_dir . '/restart_pending_*') as $f) {
                    $tn = substr(basename($f), strlen('restart_pending_'));
                    $pending[] = ['tenant' => $tn, 'queued_at' => date('c', filemtime($f))];
                }
            }
            echo json_encode(['pending' => $pending]);
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

        case 'request_device_logs':
            // Ask the agent to fetch the last N raw log lines from one of its
            // devices. Delivered on next heartbeat; result rides along on the
            // agent's NEXT snapshot after that (so ~2 heartbeats of delay —
            // shown to the user explicitly via fetched_at in the snapshot).
            $tenant = $_GET['tenant'] ?? '';
            $device_id = (int)($_GET['device_id'] ?? 0);
            $limit = max(1, min(500, (int)($_GET['limit'] ?? 100)));
            if ($tenant === '' || $device_id <= 0) {
                http_response_code(400);
                echo json_encode(['error' => 'tenant and device_id required']);
                break;
            }
            $state_dir = $config['state_dir'] ?? __DIR__ . '/state';
            if (!is_dir($state_dir)) @mkdir($state_dir, 0700, true);
            $safe = preg_replace('/[^a-zA-Z0-9_-]/', '_', $tenant);
            $marker = $state_dir . "/logs_request_{$safe}_{$device_id}_{$limit}.pending";
            file_put_contents($marker, date('c'));
            echo json_encode([
                'ok' => true, 'tenant' => $tenant, 'device_id' => $device_id, 'limit' => $limit,
                'queued_at' => date('c'),
                'note' => 'Delivered on next agent heartbeat (max 2 min); result appears in the snapshot after that.',
            ]);
            break;

        case 'pending_device_log_requests':
            $state_dir = $config['state_dir'] ?? __DIR__ . '/state';
            $pending = [];
            if (is_dir($state_dir)) {
                foreach (glob($state_dir . '/logs_request_*.pending') as $f) {
                    $base = basename($f, '.pending');
                    // logs_request_TENANT_DEVICEID_LIMIT
                    if (preg_match('/^logs_request_(.+)_(\d+)_(\d+)$/', $base, $m)) {
                        $pending[] = [
                            'tenant' => $m[1],
                            'device_id' => (int)$m[2],
                            'limit' => (int)$m[3],
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

        // Alerts
        case 'alert_channels':
            $rows = $pdo->query('SELECT id, name, type, config, enabled, created_at FROM notification_channels ORDER BY id DESC')->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$r) {
                $cfg = json_decode($r['config'] ?? '{}', true) ?: [];
                if ($r['type'] === 'telegram') {
                    $bt = (string)($cfg['bot_token'] ?? '');
                    $r['config'] = ['chat_id'=>$cfg['chat_id']??'', 'bot_token_set'=>$bt!=='', 'bot_token_suffix'=>$bt?'...'.substr($bt,-6):''];
                } elseif ($r['type'] === 'webhook') {
                    $url = (string)($cfg['url'] ?? '');
                    $r['config'] = ['url_set'=>$url!=='', 'url_host'=>$url?parse_url($url,PHP_URL_HOST):''];
                }
                $r['enabled'] = (int)$r['enabled'];
            }
            echo json_encode(['channels' => $rows]);
            break;

        case 'alert_channel_add':
            $data = json_decode(file_get_contents('php://input'), true);
            if (!is_array($data)) { http_response_code(400); echo json_encode(['error'=>'invalid body']); break; }
            $name = trim((string)($data['name']??'')); $type = (string)($data['type']??''); $cfg = $data['config'] ?? [];
            if ($name==='' || !in_array($type,['telegram','webhook'],true)) { http_response_code(400); echo json_encode(['error'=>'name and type required']); break; }
            if ($type==='telegram' && (empty($cfg['bot_token'])||empty($cfg['chat_id']))) { http_response_code(400); echo json_encode(['error'=>'bot_token and chat_id required']); break; }
            if ($type==='webhook' && (empty($cfg['url'])||!filter_var($cfg['url'],FILTER_VALIDATE_URL))) { http_response_code(400); echo json_encode(['error'=>'valid url required']); break; }
            $stmt = $pdo->prepare('INSERT INTO notification_channels (name,type,config,enabled) VALUES (?,?,?,1)');
            $stmt->execute([$name,$type,json_encode($cfg)]);
            echo json_encode(['ok'=>true,'id'=>(int)$pdo->lastInsertId()]);
            break;

        case 'alert_channel_delete':
            $id = (int)($_GET['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $stmt = $pdo->prepare('DELETE FROM notification_channels WHERE id=?'); $stmt->execute([$id]);
            echo json_encode(['ok'=>true,'deleted'=>$stmt->rowCount()]);
            break;

        case 'alert_channel_toggle':
            $id = (int)($_GET['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $pdo->prepare('UPDATE notification_channels SET enabled=1-enabled WHERE id=?')->execute([$id]);
            echo json_encode(['ok'=>true]);
            break;

        case 'alert_channel_test':
            $id = (int)($_GET['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $stmt = $pdo->prepare('SELECT * FROM notification_channels WHERE id=?'); $stmt->execute([$id]);
            $ch = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$ch) { http_response_code(404); echo json_encode(['error'=>'not found']); break; }
            $res = alerts_dispatch_channel($ch, 'test', ['type'=>'test','device_name'=>'MikroManager','device_ip'=>'127.0.0.1','count'=>0], ['name'=>'Test','id'=>0]);
            echo json_encode(['result'=>$res]);
            break;

        case 'alert_rules':
            $rows = $pdo->query('SELECT id,name,tenant,event_type,min_count,cooldown_sec,channel_ids,enabled,created_at FROM alert_rules ORDER BY id DESC')->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$r) {
                $r['channel_ids'] = json_decode($r['channel_ids']??'[]',true)?:[];
                $r['enabled']=(int)$r['enabled']; $r['min_count']=(int)$r['min_count']; $r['cooldown_sec']=(int)$r['cooldown_sec'];
            }
            echo json_encode(['rules'=>$rows]);
            break;

        case 'alert_rule_add':
            $data = json_decode(file_get_contents('php://input'), true);
            if (!is_array($data)) { http_response_code(400); echo json_encode(['error'=>'invalid body']); break; }
            $ev = (string)($data['event_type']??''); $chs = $data['channel_ids'] ?? [];
            if ($ev==='' || !is_array($chs) || empty($chs)) { http_response_code(400); echo json_encode(['error'=>'event_type and channel_ids required']); break; }
            $stmt = $pdo->prepare('INSERT INTO alert_rules (name,tenant,event_type,min_count,cooldown_sec,channel_ids,enabled) VALUES (?,?,?,?,?,?,1)');
            $stmt->execute([
                trim((string)($data['name']??''))?:null,
                trim((string)($data['tenant']??''))?:null,
                $ev, max(1,(int)($data['min_count']??1)), max(0,(int)($data['cooldown_sec']??3600)),
                json_encode(array_values(array_map('intval',$chs))),
            ]);
            echo json_encode(['ok'=>true,'id'=>(int)$pdo->lastInsertId()]);
            break;

        case 'alert_rule_delete':
            $id = (int)($_GET['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $stmt = $pdo->prepare('DELETE FROM alert_rules WHERE id=?'); $stmt->execute([$id]);
            echo json_encode(['ok'=>true,'deleted'=>$stmt->rowCount()]);
            break;

        case 'alert_rule_toggle':
            $id = (int)($_GET['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $pdo->prepare('UPDATE alert_rules SET enabled=1-enabled WHERE id=?')->execute([$id]);
            echo json_encode(['ok'=>true]);
            break;

        case 'alert_history':
            $limit = min(200, max(1, (int)($_GET['limit']??50)));
            $tenant = $_GET['tenant'] ?? '';
            if ($tenant !== '') {
                $stmt = $pdo->prepare('SELECT id,triggered_at,tenant,event_type,event_data,matched_rule_id,notifications_result FROM alert_history WHERE tenant=? ORDER BY triggered_at DESC LIMIT '.$limit);
                $stmt->execute([$tenant]);
            } else {
                $stmt = $pdo->query('SELECT id,triggered_at,tenant,event_type,event_data,matched_rule_id,notifications_result FROM alert_history ORDER BY triggered_at DESC LIMIT '.$limit);
            }
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$r) {
                $r['event_data'] = json_decode($r['event_data']??'{}',true);
                $r['notifications_result'] = json_decode($r['notifications_result']??'{}',true);
            }
            echo json_encode(['history'=>$rows]);
            break;

        // Edge monitoring
        case 'edge_devices':
            $rows = $pdo->query('SELECT id,tenant,name,ip,check_port,interval_sec,channel_ids,enabled,source,source_device_id,source_device_name,source_iface,last_seen_from_agent,last_check,last_status,last_state_change,consecutive_fails,created_at FROM edge_devices ORDER BY tenant,name')->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$r) {
                $r['channel_ids'] = json_decode($r['channel_ids']??'[]',true)?:[];
                $r['enabled']=(int)$r['enabled']; $r['interval_sec']=(int)$r['interval_sec'];
                $r['check_port'] = $r['check_port']!==null ? (int)$r['check_port'] : null;
                $r['consecutive_fails']=(int)$r['consecutive_fails'];
            }
            echo json_encode(['devices'=>$rows]);
            break;

        case 'edge_device_update':
            $data = json_decode(file_get_contents('php://input'), true);
            if (!is_array($data)) { http_response_code(400); echo json_encode(['error'=>'invalid body']); break; }
            $id = (int)($data['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $sets = []; $vals = [];
            if (array_key_exists('name',$data)) { $sets[]='name=?'; $vals[]=trim((string)$data['name']); }
            if (array_key_exists('check_port',$data)) { $sets[]='check_port=?'; $vals[] = ($data['check_port']===null||$data['check_port']==='') ? null : (int)$data['check_port']; }
            if (array_key_exists('interval_sec',$data)) { $sets[]='interval_sec=?'; $vals[]=max(60,(int)$data['interval_sec']); }
            if (array_key_exists('channel_ids',$data)) { $chs = is_array($data['channel_ids'])?$data['channel_ids']:[]; $sets[]='channel_ids=?'; $vals[]=json_encode(array_values(array_map('intval',$chs))); }
            if (empty($sets)) { echo json_encode(['ok'=>true,'no_changes'=>true]); break; }
            $vals[] = $id;
            $pdo->prepare('UPDATE edge_devices SET '.implode(',',$sets).' WHERE id=?')->execute($vals);
            echo json_encode(['ok'=>true]);
            break;

        case 'edge_device_add':
            $data = json_decode(file_get_contents('php://input'), true);
            if (!is_array($data)) { http_response_code(400); echo json_encode(['error'=>'invalid body']); break; }
            $tenant_f = trim((string)($data['tenant']??'')); $name = trim((string)($data['name']??'')); $ip = trim((string)($data['ip']??''));
            if ($tenant_f===''||$name===''||$ip==='') { http_response_code(400); echo json_encode(['error'=>'tenant, name, ip required']); break; }
            $port = isset($data['check_port'])&&$data['check_port']!=='' ? (int)$data['check_port'] : null;
            $chs = is_array($data['channel_ids']??null)?$data['channel_ids']:[];
            $stmt = $pdo->prepare('INSERT INTO edge_devices (tenant,name,ip,check_port,interval_sec,channel_ids,enabled,source) VALUES (?,?,?,?,?,?,1,"manual") ON DUPLICATE KEY UPDATE name=VALUES(name),check_port=VALUES(check_port),interval_sec=VALUES(interval_sec),channel_ids=VALUES(channel_ids),enabled=1');
            $stmt->execute([$tenant_f,$name,$ip,$port,max(60,(int)($data['interval_sec']??900)),json_encode(array_values(array_map('intval',$chs)))]);
            echo json_encode(['ok'=>true,'id'=>(int)$pdo->lastInsertId()]);
            break;

        case 'edge_device_delete':
            $id = (int)($_GET['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $pdo->prepare('DELETE FROM edge_events WHERE edge_id=?')->execute([$id]);
            $stmt = $pdo->prepare('DELETE FROM edge_devices WHERE id=?'); $stmt->execute([$id]);
            echo json_encode(['ok'=>true,'deleted'=>$stmt->rowCount()]);
            break;

        case 'edge_device_toggle':
            $id = (int)($_GET['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $pdo->prepare('UPDATE edge_devices SET enabled=1-enabled WHERE id=?')->execute([$id]);
            echo json_encode(['ok'=>true]);
            break;

        case 'edge_device_check_now':
            $id = (int)($_GET['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $stmt = $pdo->prepare('SELECT * FROM edge_devices WHERE id=?'); $stmt->execute([$id]);
            $d = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$d) { http_response_code(404); echo json_encode(['error'=>'not found']); break; }
            $res = edge_check_one($pdo,$d);
            echo json_encode(['ok'=>true,'result'=>$res]);
            break;

        case 'edge_events':
            $limit = min(200, max(1, (int)($_GET['limit']??100)));
            $edge_id = (int)($_GET['edge_id']??0);
            if ($edge_id>0) {
                $stmt = $pdo->prepare('SELECT e.id,e.edge_id,e.ts,e.event_type,e.duration_sec,e.notifications_result,d.name AS device_name,d.ip AS device_ip,d.tenant FROM edge_events e JOIN edge_devices d ON d.id=e.edge_id WHERE e.edge_id=? ORDER BY e.ts DESC LIMIT '.$limit);
                $stmt->execute([$edge_id]);
            } else {
                $stmt = $pdo->query('SELECT e.id,e.edge_id,e.ts,e.event_type,e.duration_sec,e.notifications_result,d.name AS device_name,d.ip AS device_ip,d.tenant FROM edge_events e JOIN edge_devices d ON d.id=e.edge_id ORDER BY e.ts DESC LIMIT '.$limit);
            }
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$r) {
                $r['notifications_result'] = json_decode($r['notifications_result']??'{}',true);
                $r['duration_sec'] = $r['duration_sec']!==null ? (int)$r['duration_sec'] : null;
            }
            echo json_encode(['events'=>$rows]);
            break;

        case 'activity_log':
            $limit = min(200, max(1, (int)($_GET['limit']??50)));
            $tenant = $_GET['tenant'] ?? '';
            if ($tenant !== '') {
                $stmt = $pdo->prepare('SELECT id,ts,tenant,event_type,message,details FROM activity_log WHERE tenant=? ORDER BY ts DESC LIMIT '.$limit);
                $stmt->execute([$tenant]);
            } else {
                $stmt = $pdo->query('SELECT id,ts,tenant,event_type,message,details FROM activity_log ORDER BY ts DESC LIMIT '.$limit);
            }
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$r) {
                $r['details'] = $r['details'] ? json_decode($r['details'], true) : null;
            }
            echo json_encode(['activity' => $rows]);
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
