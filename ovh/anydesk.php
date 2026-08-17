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

/** Digits-only canonical form of an AnyDesk client ID — applied to EVERY
 * cid, on every path (mapping add, REST-API sync, CSV import), so a stray
 * space/non-breaking-space/formatting artifact in one source (e.g. a CSV
 * cell) can never cause an otherwise-identical ID to silently fail to
 * match against a mapping added through a different path. */
function anydesk_normalize_cid($val): string {
    return preg_replace('/\D/', '', (string)($val ?? ''));
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

function _anydesk_prepare_upsert_stmt(PDO $pdo): PDOStatement {
    return $pdo->prepare(
        'INSERT INTO anydesk_sessions
            (anydesk_sid, tenant, from_cid, from_alias, to_cid, to_alias,
             start_time, end_time, duration_sec, billed_minutes, active, state)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            tenant = VALUES(tenant),
            end_time = VALUES(end_time),
            duration_sec = VALUES(duration_sec),
            billed_minutes = VALUES(billed_minutes),
            active = VALUES(active),
            state = VALUES(state),
            synced_at = NOW()'
    );
}

/** Normalizes + upserts ONE session row — shared by both the REST-API sync
 * path and the CSV-import path (see anydesk_import_csv_rows()) so the
 * tenant-resolution and billing-minutes math exists in exactly one place,
 * regardless of which source produced the raw data. Returns false (skipped,
 * not upserted) when required fields are missing/unparseable — one bad row
 * must never abort the whole batch. */
function anydesk_upsert_session_row(
    PDO $pdo, PDOStatement $stmt,
    string $sid, string $from_cid, string $from_alias, string $to_cid, string $to_alias,
    ?string $start_time, ?string $end_time, bool $active, ?string $state
): bool {
    if ($sid === '' || $from_cid === '' || $to_cid === '' || $start_time === null) {
        return false;
    }

    $duration_sec = null;
    $billed_minutes = null;
    if (!$active && $end_time !== null) {
        $duration_sec = max(0, strtotime($end_time) - strtotime($start_time));
        $billed_minutes = max(15, (int)ceil($duration_sec / 900) * 15);
    }

    $tenant = _anydesk_resolve_tenant($pdo, $from_cid, $to_cid);

    $stmt->execute([
        $sid, $tenant, $from_cid, $from_alias, $to_cid, $to_alias,
        $start_time, $end_time, $duration_sec, $billed_minutes, $active ? 1 : 0, $state,
    ]);
    return true;
}

/** Core sync — fetches the full current session list from AnyDesk and
 * upserts it into anydesk_sessions (deduped by anydesk_sid). Never throws;
 * every failure mode returns {ok:false, error}. Requires a Standard-or-above
 * AnyDesk license (Solo has no REST-API) — see anydesk_import_csv_rows()
 * for the CSV-based alternative that works on any license. */
function anydesk_sync(PDO $pdo, array $config): array {
    $result = anydesk_api_get($config, 'sessions');
    if (!$result['ok']) {
        _anydesk_save_sync_state($config, $result['error'] ?? 'unknown error');
        return ['ok' => false, 'error' => $result['error'] ?? 'unknown error', 'synced' => 0];
    }

    $list = $result['data']['list'] ?? [];
    if (!is_array($list)) $list = [];

    $stmt = _anydesk_prepare_upsert_stmt($pdo);

    $synced = 0;
    $skipped = 0;
    foreach ($list as $session) {
        if (!is_array($session)) { $skipped++; continue; }
        $sid = (string)($session['sid'] ?? '');
        $from_cid = anydesk_normalize_cid($session['from']['cid'] ?? '');
        $to_cid = anydesk_normalize_cid($session['to']['cid'] ?? '');
        $start_time = anydesk_parse_time($session['start-time'] ?? null);
        $end_time = anydesk_parse_time($session['end-time'] ?? null);
        $active = !empty($session['active']);

        $ok = anydesk_upsert_session_row(
            $pdo, $stmt, $sid, $from_cid, (string)($session['from']['alias'] ?? ''),
            $to_cid, (string)($session['to']['alias'] ?? ''),
            $start_time, $end_time, $active, null
        );
        $ok ? $synced++ : $skipped++;
    }

    _anydesk_save_sync_state($config, null);
    return ['ok' => true, 'error' => null, 'synced' => $synced, 'skipped' => $skipped];
}

/** Parses AnyDesk's own "Eksportuj do pliku CSV" export from the Sessions
 * page of my.anydesk.com (confirmed header, real sample data): sessionId,
 * state, sourceClientId, sourceClientAlias, destinationClientId,
 * destinationClientAlias, started, ended, sourceComment, destinationComment,
 * receivedBytes, sentBytes, sourceCountry, destinationCountry — of which
 * only the first eight are used here. started/ended are strict ISO8601 UTC
 * with milliseconds ("2026-08-16T16:27:25.000Z"), which PHP's strtotime()
 * (via anydesk_parse_time()) parses unambiguously.
 *
 * Column POSITIONS are not assumed — the header row is read and mapped to
 * indices dynamically, so a future AnyDesk export with reordered/added
 * columns doesn't silently misparse. Malformed rows (wrong column count)
 * are skipped, never fatal. */
function anydesk_parse_csv_content(string $csv_text): array {
    $required = ['sessionId', 'state', 'sourceClientId', 'sourceClientAlias', 'destinationClientId', 'destinationClientAlias', 'started', 'ended'];

    // Strip a UTF-8 BOM if present — confirmed present in a real export from
    // my.anydesk.com; left in place it corrupts the FIRST header name
    // (sessionId becomes "\xEF\xBB\xBFsessionId"), silently failing the
    // required-column check below.
    if (substr($csv_text, 0, 3) === "\xEF\xBB\xBF") {
        $csv_text = substr($csv_text, 3);
    }

    $fh = fopen('php://temp', 'r+');
    fwrite($fh, $csv_text);
    rewind($fh);

    $header = fgetcsv($fh);
    if ($header === false || $header === null) {
        fclose($fh);
        return ['rows' => [], 'error' => 'empty file'];
    }
    $index = array_flip($header);
    foreach ($required as $col) {
        if (!isset($index[$col])) {
            fclose($fh);
            return ['rows' => [], 'error' => "missing expected column: {$col}"];
        }
    }

    $rows = [];
    while (($fields = fgetcsv($fh)) !== false) {
        if ($fields === null || count($fields) !== count($header)) continue; // malformed line, skip
        $row = [];
        foreach ($index as $col => $i) $row[$col] = $fields[$i] ?? '';
        $rows[] = $row;
    }
    fclose($fh);
    return ['rows' => $rows, 'error' => null];
}

/** Imports already-parsed CSV rows (see anydesk_parse_csv_content()) using
 * the same upsert/tenant-resolution/billing logic as the REST-API sync —
 * works on ANY AnyDesk license tier, since it needs no API credentials.
 * "ended" empty (not yet closed at export time) is treated as still-active,
 * same convention as the REST-API path. */
function anydesk_import_csv_rows(PDO $pdo, array $rows): array {
    $stmt = _anydesk_prepare_upsert_stmt($pdo);
    $imported = 0;
    $skipped = 0;
    foreach ($rows as $row) {
        $sid = (string)($row['sessionId'] ?? '');
        $from_cid = anydesk_normalize_cid($row['sourceClientId'] ?? '');
        $to_cid = anydesk_normalize_cid($row['destinationClientId'] ?? '');
        $start_time = anydesk_parse_time($row['started'] ?? null);
        $end_time = anydesk_parse_time($row['ended'] ?? null);
        $state = trim((string)($row['state'] ?? '')) ?: null;
        $active = $end_time === null;

        $ok = anydesk_upsert_session_row(
            $pdo, $stmt, $sid, $from_cid, (string)($row['sourceClientAlias'] ?? ''),
            $to_cid, (string)($row['destinationClientAlias'] ?? ''),
            $start_time, $end_time, $active, $state
        );
        $ok ? $imported++ : $skipped++;
    }
    return ['ok' => true, 'imported' => $imported, 'skipped' => $skipped];
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
