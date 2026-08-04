<?php
/**
 * MikroManager central — notification dispatch.
 *
 * Called from ingest.php after receiving alert_events in the snapshot envelope.
 * Matches events against configured alert_rules and dispatches to channels
 * (Telegram Bot API, generic webhook).
 *
 * No external dependencies — pure PHP with file_get_contents() HTTP client.
 */

declare(strict_types=1);


function alerts_process(PDO $pdo, string $tenant, array $events): void {
    if (empty($events)) return;

    $stmt = $pdo->prepare(
        'SELECT * FROM alert_rules
         WHERE enabled = 1
           AND (tenant = ? OR tenant IS NULL OR tenant = "")'
    );
    $stmt->execute([$tenant]);
    $rules = $stmt->fetchAll(PDO::FETCH_ASSOC);
    if (empty($rules)) return;

    foreach ($events as $event) {
        if (!is_array($event)) continue;
        $ev_type = $event['type'] ?? '';
        if ($ev_type === '') continue;
        $ev_count = (int)($event['count'] ?? 0);

        foreach ($rules as $rule) {
            if ($rule['event_type'] !== $ev_type) continue;
            if ($ev_count < (int)$rule['min_count']) continue;

            // Cooldown check — do not re-fire same rule for same tenant within window.
            $cooldown = (int)$rule['cooldown_sec'];
            if ($cooldown > 0) {
                $stmt = $pdo->prepare(
                    'SELECT COUNT(*) FROM alert_history
                     WHERE tenant = ? AND matched_rule_id = ?
                       AND triggered_at > DATE_SUB(NOW(), INTERVAL ? SECOND)'
                );
                $stmt->execute([$tenant, $rule['id'], $cooldown]);
                if ((int)$stmt->fetchColumn() > 0) continue;
            }

            $channel_ids = json_decode($rule['channel_ids'] ?? '[]', true);
            if (!is_array($channel_ids)) $channel_ids = [];

            $results = [];
            foreach ($channel_ids as $cid) {
                $ch = alerts_get_channel($pdo, (int)$cid);
                if (!$ch) {
                    $results[(string)$cid] = ['ok' => false, 'error' => 'channel not found or disabled'];
                    continue;
                }
                $results[(string)$cid] = alerts_dispatch_channel($ch, $tenant, $event, $rule);
            }

            $stmt = $pdo->prepare(
                'INSERT INTO alert_history
                   (tenant, event_type, event_data, matched_rule_id, notifications_result)
                 VALUES (?, ?, ?, ?, ?)'
            );
            $stmt->execute([
                $tenant, $ev_type, json_encode($event),
                (int)$rule['id'], json_encode($results),
            ]);
        }
    }

    // Cap history size: keep 500 newest per tenant.
    $stmt = $pdo->prepare(
        'DELETE FROM alert_history
         WHERE tenant = ?
           AND id NOT IN (
             SELECT id FROM (
               SELECT id FROM alert_history WHERE tenant = ? ORDER BY triggered_at DESC LIMIT 500
             ) t
           )'
    );
    $stmt->execute([$tenant, $tenant]);
}


function alerts_get_channel(PDO $pdo, int $id): ?array {
    $stmt = $pdo->prepare('SELECT * FROM notification_channels WHERE id = ? AND enabled = 1');
    $stmt->execute([$id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ?: null;
}


function alerts_dispatch_channel(array $channel, string $tenant, array $event, array $rule): array {
    $cfg = json_decode($channel['config'] ?? '{}', true);
    if (!is_array($cfg)) $cfg = [];
    $message = alerts_format_message($tenant, $event, $rule);

    switch ($channel['type']) {
        case 'telegram':
            return alerts_send_telegram(
                (string)($cfg['bot_token'] ?? ''),
                (string)($cfg['chat_id'] ?? ''),
                $message
            );
        case 'webhook':
            return alerts_send_webhook(
                (string)($cfg['url'] ?? ''),
                [
                    'tenant' => $tenant,
                    'event' => $event,
                    'rule_name' => $rule['name'] ?? null,
                    'message' => $message,
                ]
            );
        default:
            return ['ok' => false, 'error' => 'unknown channel type'];
    }
}


function alerts_format_message(string $tenant, array $event, array $rule): string {
    $type = $event['type'] ?? '?';
    $device = $event['device_name'] ?? $event['device_ip'] ?? '?';
    $ruleName = $rule['name'] ?? '';
    $prefix = $ruleName ? "[$ruleName] " : '';

    switch ($type) {
        case 'failed_logins':
            $count = (int)($event['count'] ?? 0);
            $window_min = round((int)($event['window_sec'] ?? 900) / 60);
            $sources = is_array($event['sources'] ?? null)
                ? implode(', ', array_slice($event['sources'], 0, 5))
                : '';
            $users = is_array($event['users'] ?? null)
                ? implode(', ', array_slice($event['users'], 0, 5))
                : '';
            $msg = "🚨 {$prefix}MikroManager alert\n"
                 . "Tenant: {$tenant}\n"
                 . "Urządzenie: {$device}\n"
                 . "Nieudane próby logowania: {$count} (ostatnie {$window_min} min)";
            if ($sources !== '') $msg .= "\nŹródła IP: {$sources}";
            if ($users !== '') $msg .= "\nUżytkownicy: {$users}";
            return $msg;
        default:
            return "⚠️ {$prefix}[{$tenant}] Alert {$type} na {$device}";
    }
}


function alerts_http_post(string $url, string $body, string $content_type, int $timeout = 10): array {
    $ctx = stream_context_create([
        'http' => [
            'method'        => 'POST',
            'header'        => "Content-Type: {$content_type}\r\nContent-Length: " . strlen($body) . "\r\n",
            'content'       => $body,
            'timeout'       => $timeout,
            'ignore_errors' => true,
        ],
    ]);
    $resp = @file_get_contents($url, false, $ctx);
    $status = 0;
    if (isset($http_response_header[0])
        && preg_match('#HTTP/\S+\s+(\d+)#', $http_response_header[0], $mm)) {
        $status = (int)$mm[1];
    }
    if ($resp === false) {
        return ['ok' => false, 'error' => 'HTTP connection failed'];
    }
    if ($status < 200 || $status >= 300) {
        return ['ok' => false, 'status' => $status, 'error' => substr((string)$resp, 0, 200)];
    }
    return ['ok' => true, 'status' => $status];
}


function alerts_send_telegram(string $bot_token, string $chat_id, string $text): array {
    if ($bot_token === '' || $chat_id === '') {
        return ['ok' => false, 'error' => 'missing bot_token or chat_id'];
    }
    $url = "https://api.telegram.org/bot{$bot_token}/sendMessage";
    $body = http_build_query([
        'chat_id' => $chat_id,
        'text'    => $text,
        'disable_web_page_preview' => 'true',
    ]);
    return alerts_http_post($url, $body, 'application/x-www-form-urlencoded');
}


function alerts_send_webhook(string $url, array $data): array {
    if ($url === '') return ['ok' => false, 'error' => 'missing url'];
    return alerts_http_post($url, json_encode($data), 'application/json');
}


// ── Edge device availability (v1.5) ────────────────────────────────────────

/**
 * Check reachability of a single IP.
 * If $port is provided, does a TCP connect on that port (works around ICMP
 * being blocked/exec disabled). Otherwise runs system ping with a short timeout.
 * Falls back automatically: if ICMP unavailable, tries TCP on port 80.
 *
 * Returns true if reachable, false if unreachable.
 */
function edge_check_ip(string $ip, ?int $port = null, int $timeout = 3): bool {
    if ($port !== null && $port > 0) {
        return edge_tcp_check($ip, $port, $timeout);
    }
    // Try ICMP first
    if (function_exists('exec')) {
        $safe = escapeshellarg($ip);
        $cmd = stripos(PHP_OS, 'WIN') === 0
            ? "ping -n 1 -w " . ($timeout * 1000) . " $safe"
            : "ping -c 1 -W $timeout $safe 2>/dev/null";
        $out = []; $code = 1;
        @exec($cmd, $out, $code);
        if ($code === 0) return true;
        // If exec worked but ping failed, honor the result — don't fallback
        // (avoid false positives just because port 80 responds while ICMP is down)
        return false;
    }
    // exec disabled → best-effort TCP fallback to 80
    return edge_tcp_check($ip, 80, $timeout);
}


function edge_tcp_check(string $ip, int $port, int $timeout = 3): bool {
    $err_no = 0; $err_str = '';
    $sock = @fsockopen($ip, $port, $err_no, $err_str, $timeout);
    if ($sock) { @fclose($sock); return true; }
    return false;
}


/**
 * Check every enabled edge device whose last_check is older than its
 * interval_sec. Records state changes to edge_events and dispatches
 * notifications to configured channels.
 *
 * Runs at most for $max_seconds to avoid blocking the caller (ingest.php).
 * Remaining devices will be checked on the next tick.
 */
function edge_check_due(PDO $pdo, int $max_seconds = 8): int {
    $stmt = $pdo->query(
        "SELECT * FROM edge_devices
         WHERE enabled = 1
           AND (last_check IS NULL
                OR TIMESTAMPDIFF(SECOND, last_check, NOW()) >= interval_sec)
         ORDER BY last_check IS NULL DESC, last_check ASC
         LIMIT 40"
    );
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $started = microtime(true);
    $checked = 0;

    foreach ($devices as $d) {
        if ((microtime(true) - $started) > $max_seconds) break;
        edge_check_one($pdo, $d);
        $checked++;
    }
    return $checked;
}


function edge_check_one(PDO $pdo, array $d): array {
    $ip = (string)$d['ip'];
    $port = $d['check_port'] !== null ? (int)$d['check_port'] : null;
    $ok = edge_check_ip($ip, $port);

    $prev = $d['last_status'];
    $consecutive = (int)$d['consecutive_fails'];
    $new_status = $ok ? 'online' : 'offline';

    // State-change rule: transition to offline only after 2 consecutive fails
    // (avoids flapping on a single dropped packet). Online transition is immediate.
    if ($ok) {
        $consecutive = 0;
        $effective = 'online';
    } else {
        $consecutive++;
        $effective = $consecutive >= 2 ? 'offline' : $prev;  // stay in prev if just 1 fail
        if ($prev === 'unknown') $effective = 'offline';     // no debounce on first ever check
    }

    $state_changed = ($prev !== $effective);
    $now = date('Y-m-d H:i:s');

    // Update device row
    if ($state_changed) {
        $stmt = $pdo->prepare(
            "UPDATE edge_devices
             SET last_check = ?, last_status = ?, last_state_change = ?, consecutive_fails = ?
             WHERE id = ?"
        );
        $stmt->execute([$now, $effective, $now, $consecutive, $d['id']]);
    } else {
        $stmt = $pdo->prepare(
            "UPDATE edge_devices
             SET last_check = ?, consecutive_fails = ?
             WHERE id = ?"
        );
        $stmt->execute([$now, $consecutive, $d['id']]);
    }

    $result = ['ok' => $ok, 'state_changed' => $state_changed, 'new_status' => $effective];

    if (!$state_changed) return $result;

    // Compute duration if returning online (from last offline event)
    $duration_sec = null;
    if ($effective === 'online' && $prev === 'offline') {
        $stmt = $pdo->prepare(
            "SELECT UNIX_TIMESTAMP(ts) FROM edge_events
             WHERE edge_id = ? AND event_type = 'offline'
             ORDER BY ts DESC LIMIT 1"
        );
        $stmt->execute([$d['id']]);
        $off_ts = (int)$stmt->fetchColumn();
        if ($off_ts > 0) $duration_sec = time() - $off_ts;
    }

    // Dispatch notifications
    $channel_ids = json_decode($d['channel_ids'] ?? '[]', true) ?: [];
    $notif_results = [];
    foreach ($channel_ids as $cid) {
        $ch = alerts_get_channel($pdo, (int)$cid);
        if (!$ch) { $notif_results[(string)$cid] = ['ok'=>false,'error'=>'channel not found']; continue; }
        $msg = edge_format_message($d, $effective, $duration_sec);
        $notif_results[(string)$cid] = edge_dispatch($ch, $msg);
    }

    $stmt = $pdo->prepare(
        "INSERT INTO edge_events (edge_id, event_type, duration_sec, notifications_result)
         VALUES (?, ?, ?, ?)"
    );
    $stmt->execute([
        $d['id'], $effective, $duration_sec, json_encode($notif_results),
    ]);

    // Cap event history: keep 500 newest per device
    $stmt = $pdo->prepare(
        "DELETE FROM edge_events WHERE edge_id = ? AND id NOT IN (
             SELECT id FROM (
                 SELECT id FROM edge_events WHERE edge_id = ? ORDER BY ts DESC LIMIT 500
             ) t
         )"
    );
    $stmt->execute([$d['id'], $d['id']]);

    $result['duration_sec'] = $duration_sec;
    $result['notifications'] = $notif_results;
    return $result;
}


function edge_format_message(array $d, string $status, ?int $duration_sec): string {
    $name = $d['name'];
    $ip = $d['ip'];
    $tenant = $d['tenant'];
    $ts = date('Y-m-d H:i');
    if ($status === 'offline') {
        return "🔴 [{$tenant}] Przerwa w dostępie\n"
             . "Urządzenie: {$name} ({$ip})\n"
             . "Od: {$ts}";
    } else {
        $dur_txt = $duration_sec !== null ? edge_format_duration($duration_sec) : '?';
        return "🟢 [{$tenant}] Urządzenie znowu online\n"
             . "Urządzenie: {$name} ({$ip})\n"
             . "Powr\u{00F3}t: {$ts}\n"
             . "Czas przerwy: {$dur_txt}";
    }
}


function edge_format_duration(int $sec): string {
    if ($sec < 60) return "{$sec}s";
    if ($sec < 3600) return floor($sec / 60) . 'm ' . ($sec % 60) . 's';
    $h = floor($sec / 3600);
    $m = floor(($sec % 3600) / 60);
    return "{$h}h {$m}m";
}


function edge_dispatch(array $channel, string $message): array {
    $cfg = json_decode($channel['config'] ?? '{}', true) ?: [];
    switch ($channel['type']) {
        case 'telegram':
            return alerts_send_telegram(
                (string)($cfg['bot_token'] ?? ''),
                (string)($cfg['chat_id'] ?? ''),
                $message
            );
        case 'webhook':
            return alerts_send_webhook(
                (string)($cfg['url'] ?? ''),
                ['type' => 'edge_status', 'message' => $message]
            );
        default:
            return ['ok' => false, 'error' => 'unknown channel type'];
    }
}


/**
 * Sync edge_devices from an agent's snapshot metadata (v1.6).
 *
 * Reconciles the DB against the current WAN IPs reported by this tenant:
 *   - unknown (tenant, ip) → insert new row (enabled=0, source='auto')
 *   - existing auto row    → update last_seen_from_agent + name/iface
 *   - auto rows for this tenant not present in current list AND stale
 *     (>7 days) → delete (device removed or WAN IP rotated)
 *
 * Manually added rows (source='manual') are never touched here.
 */
function edge_sync_from_agent(PDO $pdo, string $tenant, array $edge_ips): void {
    if (empty($edge_ips)) return;
    $now = date('Y-m-d H:i:s');
    $seen_ips = [];

    foreach ($edge_ips as $e) {
        if (!is_array($e)) continue;
        $ip = trim((string)($e['ip'] ?? ''));
        if ($ip === '') continue;
        $seen_ips[] = $ip;
        $device_id = isset($e['device_id']) ? (int)$e['device_id'] : null;
        $device_name = (string)($e['device_name'] ?? '');
        $iface = (string)($e['iface'] ?? '');
        $default_name = $device_name !== '' ? "{$device_name} ({$iface})" : $ip;

        $stmt = $pdo->prepare(
            'INSERT INTO edge_devices
               (tenant, name, ip, source, source_device_id, source_device_name,
                source_iface, last_seen_from_agent, channel_ids, enabled)
             VALUES (?, ?, ?, "auto", ?, ?, ?, ?, "[]", 0)
             ON DUPLICATE KEY UPDATE
               source_device_id = VALUES(source_device_id),
               source_device_name = VALUES(source_device_name),
               source_iface = VALUES(source_iface),
               last_seen_from_agent = VALUES(last_seen_from_agent)'
        );
        $stmt->execute([$tenant, $default_name, $ip, $device_id, $device_name, $iface, $now]);
    }

    // Prune stale auto rows for this tenant that weren't in this snapshot
    // AND haven't been seen for a week (grace period for transient reporting).
    $stmt = $pdo->prepare(
        "DELETE FROM edge_devices
         WHERE tenant = ? AND source = 'auto'
           AND (last_seen_from_agent IS NULL
                OR last_seen_from_agent < DATE_SUB(NOW(), INTERVAL 7 DAY))"
    );
    $stmt->execute([$tenant]);
}
