<?php
/**
 * MikroManager central — AnyDesk time-tracking sync.
 *
 * Talks to AnyDesk's own REST API (https://v1.api.anydesk.com:8081/) to pull
 * this account's session history and turn it into per-tenant billed minutes.
 * HMAC-SHA1 request signing reimplemented from AnyDesk's official reference
 * client (github.com/anydesk/rest-api) — no external dependencies, pure PHP
 * with file_get_contents(), same convention as notifications.php.
 *
 * Deliberately does NOT trust the API's start/end query filters (the
 * reference client's own filter helper looks buggy — it builds a "clients?"
 * URL while documenting session-list filters) — always pulls the full
 * current session list and filters/dedupes on this side.
 */

declare(strict_types=1);

const ANYDESK_API_BASE = 'https://v1.api.anydesk.com:8081/';


function anydesk_auth_header(string $license, string $key, string $method, string $resource, string $content = ''): string {
    $content_hash = base64_encode(hash('sha1', $content, true));
    $timestamp = (string)time();
    $request_string = $method . "\n" . $resource . "\n" . $timestamp . "\n" . $content_hash;
    $token = base64_encode(hash_hmac('sha1', $request_string, $key, true));
    return 'AD ' . $license . ':' . $timestamp . ':' . $token;
}

function anydesk_api_get(array $config, string $resource): array {
    $license = (string)($config['anydesk_license_id'] ?? '');
    $key = (string)($config['anydesk_api_key'] ?? '');
    if ($license === '' || $key === '') {
        return ['ok' => false, 'error' => 'not_configured'];
    }
    $auth = anydesk_auth_header($license, $key, 'GET', '/' . $resource);
    $ctx = stream_context_create([
        'http' => [
            'method'        => 'GET',
            'header'        => "Authorization: {$auth}\r\n",
            'timeout'       => 15,
            'ignore_errors' => true,
        ],
    ]);
    $resp = @file_get_contents(ANYDESK_API_BASE . $resource, false, $ctx);
    $status = 0;
    if (isset($http_response_header[0])
        && preg_match('#HTTP/\S+\s+(\d+)#', $http_response_header[0], $mm)) {
        $status = (int)$mm[1];
    }
    if ($resp === false) {
        return ['ok' => false, 'error' => 'connection failed'];
    }
    if ($status < 200 || $status >= 300) {
        return ['ok' => false, 'status' => $status, 'error' => substr((string)$resp, 0, 300)];
    }
    $data = json_decode((string)$resp, true);
    if (!is_array($data)) {
        return ['ok' => false, 'error' => 'invalid JSON response'];
    }
    return ['ok' => true, 'data' => $data];
}

/** Accepts either an ISO8601 string or a Unix-epoch numeric string/int —
 * the exact shape AnyDesk's API returns for start-time/end-time hasn't been
 * confirmed against live data yet (see plan's Verification section), so
 * this stays permissive rather than assuming one format. Returns null (not
 * an exception) on anything unparseable — one bad record must never abort
 * the whole sync. */
function anydesk_parse_time($val): ?string {
    if ($val === null || $val === '') return null;
    if (is_numeric($val)) {
        $ts = (int)$val;
        return $ts > 0 ? date('Y-m-d H:i:s', $ts) : null;
    }
    $ts = strtotime((string)$val);
    return $ts !== false ? date('Y-m-d H:i:s', $ts) : null;
}

function _anydesk_sync_state_path(array $config): string {
    $dir = $config['state_dir'];
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    return $dir . '/anydesk_sync_state.json';
}

function anydesk_sync_state(array $config): array {
    $path = _anydesk_sync_state_path($config);
    if (!is_file($path)) {
        return ['last_sync_at' => null, 'last_error' => null];
    }
    $data = json_decode((string)file_get_contents($path), true);
    return is_array($data) ? $data : ['last_sync_at' => null, 'last_error' => null];
}

function _anydesk_save_sync_state(array $config, ?string $error): void {
    $path = _anydesk_sync_state_path($config);
    file_put_contents($path, json_encode([
        'last_sync_at' => date('c'),
        'last_error'   => $error,
    ]), LOCK_EX);
}

/** Resolve which tenant (if any) a session belongs to by checking both
 * ends against anydesk_client_map — the operator usually connects OUT to
 * the client's device (to.cid), but checking from.cid too covers the rare
 * case of the client connecting in to demo/hand off control. */
function _anydesk_resolve_tenant(PDO $pdo, string $from_cid, string $to_cid): ?string {
    static $map = null;
    if ($map === null) {
        $map = [];
        $rows = $pdo->query('SELECT tenant, anydesk_cid FROM anydesk_client_map')->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as $r) $map[$r['anydesk_cid']] = $r['tenant'];
    }
    if (isset($map[$to_cid])) return $map[$to_cid];
    if (isset($map[$from_cid])) return $map[$from_cid];
    return null;
}

/** Core sync — fetches the full current session list from AnyDesk and
 * upserts it into anydesk_sessions (deduped by anydesk_sid). Never throws;
 * every failure mode returns {ok:false, error}. */
function anydesk_sync(PDO $pdo, array $config): array {
    $result = anydesk_api_get($config, 'sessions');
    if (!$result['ok']) {
        _anydesk_save_sync_state($config, $result['error'] ?? 'unknown error');
        return ['ok' => false, 'error' => $result['error'] ?? 'unknown error', 'synced' => 0];
    }

    $list = $result['data']['list'] ?? [];
    if (!is_array($list)) $list = [];

    $stmt = $pdo->prepare(
        'INSERT INTO anydesk_sessions
            (anydesk_sid, tenant, from_cid, from_alias, to_cid, to_alias,
             start_time, end_time, duration_sec, billed_minutes, active)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            tenant = VALUES(tenant),
            end_time = VALUES(end_time),
            duration_sec = VALUES(duration_sec),
            billed_minutes = VALUES(billed_minutes),
            active = VALUES(active),
            synced_at = NOW()'
    );

    $synced = 0;
    $skipped = 0;
    foreach ($list as $session) {
        if (!is_array($session)) { $skipped++; continue; }
        $sid = (string)($session['sid'] ?? '');
        $from_cid = (string)($session['from']['cid'] ?? '');
        $to_cid = (string)($session['to']['cid'] ?? '');
        $start_time = anydesk_parse_time($session['start-time'] ?? null);
        if ($sid === '' || $from_cid === '' || $to_cid === '' || $start_time === null) {
            $skipped++;
            continue;
        }
        $end_time = anydesk_parse_time($session['end-time'] ?? null);
        $active = !empty($session['active']) ? 1 : 0;

        $duration_sec = null;
        $billed_minutes = null;
        if (!$active && $end_time !== null) {
            $duration_sec = max(0, strtotime($end_time) - strtotime($start_time));
            $billed_minutes = max(15, (int)ceil($duration_sec / 900) * 15);
        }

        $tenant = _anydesk_resolve_tenant($pdo, $from_cid, $to_cid);

        $stmt->execute([
            $sid, $tenant, $from_cid, (string)($session['from']['alias'] ?? ''),
            $to_cid, (string)($session['to']['alias'] ?? ''),
            $start_time, $end_time, $duration_sec, $billed_minutes, $active,
        ]);
        $synced++;
    }

    _anydesk_save_sync_state($config, null);
    return ['ok' => true, 'error' => null, 'synced' => $synced, 'skipped' => $skipped];
}

/** Opportunistic sync — piggybacks on normal traffic instead of relying on
 * a cron the shared-hosting plan may not have, same philosophy as
 * mm_session_gc() in api.php. Never lets a sync failure break the request
 * that triggered it. */
function anydesk_maybe_sync(PDO $pdo, array $config): void {
    $state = anydesk_sync_state($config);
    $last = $state['last_sync_at'] ?? null;
    if ($last !== null && (time() - strtotime($last)) < 900) {
        return;
    }
    try {
        anydesk_sync($pdo, $config);
    } catch (Throwable $e) {
        _anydesk_save_sync_state($config, $e->getMessage());
    }
}
