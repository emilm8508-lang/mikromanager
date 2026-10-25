<?php
/**
 * MikroManager central — NVD proxy for the agents, and the place where the organisation's NVD API key lives.
 *
 * The NVD API key (free, one per requester - see https://nvd.nist.gov/developers/request-an-api-key) is kept HERE, in the central database
 * (table central_settings), never on an agent: the agents ask this script for the NVD lookups of their vulnerability scan, the script adds the key,
 * asks NVD, remembers the answer for a day (a CVE for a week) so that the same product asked by many clients costs one NVD request, and keeps the
 * spacing NVD requires between requests across ALL agents. The key is write-only: no endpoint returns it.
 *
 *   POST nvd.php?action=lookup   (agents)  signed like ingest.php: Authorization: Bearer <tenant api_key>, X-Tenant, X-Timestamp,
 *                                          X-Signature = HMAC-SHA256(api_key, timestamp || "|" || body); body {"kind": "cves"|"cpes", "params": {...}}.
 *                                          Answers with NVD's own JSON (header X-Nvd-Cache: hit | miss | stale); 503 {"error":"no_key"} when no key is set
 *                                          (the agent then asks NVD itself, slowly); 429 when the queue for NVD is too long.
 *   GET  nvd.php?action=status             (global administrator: a user session, or the legacy viewer password) whether a key is set, who set it
 *                                          and when, the use in the last 24 hours per client.
 *   POST nvd.php?action=key_set            (global administrator) body {"key": "..."} - checked with NVD before it is kept.
 *   POST nvd.php?action=key_clear          (global administrator)
 *
 * Self-contained on purpose: a mistake in this file can only affect NVD lookups, never the ingest or the viewer API. The tables are created on first use.
 */

declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

$config = require __DIR__ . '/config.php';

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/';
const NVD_INTERVAL_US = 700000;      // 0.7 s between requests to NVD (it allows 50 per 30 s with a key)
const NVD_MAX_WAIT_S = 15;           // a request that would wait longer than this for its turn is refused with 429
const NVD_TTL_QUERY = 86400;         // product / CPE searches are remembered for 24 hours ...
const NVD_TTL_CVE = 604800;          // ... one CVE by its id for 7 days
const NVD_TENANT_PER_MIN = 240;      // per client
const NVD_MAX_BODY = 8192;

function nvd_fail(int $code, string $msg, array $extra = []): void {
    http_response_code($code);
    echo json_encode(array_merge(['error' => $msg], $extra));
    exit;
}

function nvd_header(string $name): string {
    $upper = strtoupper(str_replace('-', '_', $name));
    foreach (["HTTP_$upper", "REDIRECT_HTTP_$upper"] as $key) {
        if (!empty($_SERVER[$key])) return (string)$_SERVER[$key];
    }
    if (function_exists('getallheaders')) {
        foreach (getallheaders() as $k => $v) {
            if (strcasecmp((string)$k, $name) === 0) return (string)$v;
        }
    }
    return '';
}

function nvd_pdo(array $config): PDO {
    $dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', $config['db']['host'], $config['db']['name']);
    return new PDO($dsn, $config['db']['user'], $config['db']['password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
}

function nvd_tables(PDO $pdo): void {
    $pdo->exec('CREATE TABLE IF NOT EXISTS central_settings (
        name VARCHAR(64) NOT NULL PRIMARY KEY, value TEXT NULL, updated_at DATETIME NULL, updated_by VARCHAR(64) NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    $pdo->exec('CREATE TABLE IF NOT EXISTS nvd_cache (
        cache_key CHAR(40) NOT NULL PRIMARY KEY, body MEDIUMTEXT NOT NULL, fetched_at DATETIME NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    $pdo->exec('CREATE TABLE IF NOT EXISTS nvd_usage (
        usage_day DATE NOT NULL, tenant VARCHAR(64) NOT NULL, requests INT NOT NULL DEFAULT 0, upstream INT NOT NULL DEFAULT 0,
        PRIMARY KEY (usage_day, tenant)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
}

function nvd_get_key(PDO $pdo): string {
    $st = $pdo->prepare('SELECT value FROM central_settings WHERE name = ?');
    $st->execute(['nvd_api_key']);
    $v = $st->fetchColumn();
    return $v === false || $v === null ? '' : trim((string)$v);
}

function nvd_ip_in_cidr(string $ip, string $cidr): bool {
    if (strpos($cidr, '/') === false) return $ip === $cidr;
    [$subnet, $bits] = explode('/', $cidr, 2);
    $bits = (int)$bits;
    $ipL = ip2long($ip);
    $subL = ip2long($subnet);
    if ($ipL === false || $subL === false) return false;
    $mask = $bits === 0 ? 0 : -1 << (32 - $bits);
    return ($ipL & $mask) === ($subL & $mask);
}

/** A counter per name and window kept in the state dir (the same simple mechanism as the ingest rate limit). Returns the count including this call. */
function nvd_counter(array $config, string $name, int $window_sec, bool $increment = true): int {
    $dir = (string)($config['state_dir'] ?? (__DIR__ . '/state'));
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $bucket = (int)(time() / $window_sec);
    $path = $dir . '/nvd_' . preg_replace('/[^a-zA-Z0-9_-]/', '_', $name) . '_' . $bucket;
    $count = is_file($path) ? (int)file_get_contents($path) : 0;
    if (!$increment) return $count;
    $count++;
    @file_put_contents($path, (string)$count, LOCK_EX);
    if (random_int(0, 99) === 0) {
        foreach (glob($dir . '/nvd_*') ?: [] as $f) {
            if (basename($f) !== 'nvd_throttle' && filemtime($f) < time() - 2 * $window_sec - 900) @unlink($f);
        }
    }
    return $count;
}

/** The agent's request: tenant, key, source address, timestamp and HMAC are checked exactly as ingest.php does. Returns [tenant, body]. */
function nvd_agent_auth(array $config): array {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') nvd_fail(405, 'POST required');
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    if (nvd_counter($config, 'ip_' . $ip, 60) > 600) nvd_fail(429, 'rate limit exceeded');

    if (!preg_match('/Bearer\s+(.+)/i', nvd_header('Authorization'), $m)) nvd_fail(401, 'missing or malformed Authorization header');
    $provided = trim($m[1]);
    $tenant = trim(nvd_header('X-Tenant'));
    if ($tenant === '' || !isset($config['tenants'][$tenant])) nvd_fail(401, 'unknown tenant');
    $tcfg = $config['tenants'][$tenant];
    $expected = (string)($tcfg['api_key'] ?? '');
    if ($expected === '' || !hash_equals($expected, $provided)) nvd_fail(401, 'invalid api key');

    $ok = false;
    foreach (($tcfg['allow_ips'] ?? ['0.0.0.0/0']) as $cidr) {
        if (nvd_ip_in_cidr($ip, (string)$cidr)) { $ok = true; break; }
    }
    if (!$ok) nvd_fail(403, 'source IP not in tenant allowlist');

    $body = file_get_contents('php://input');
    if ($body === false || strlen($body) === 0) nvd_fail(400, 'empty body');
    if (strlen($body) > NVD_MAX_BODY) nvd_fail(413, 'payload too large');

    $ts_header = nvd_header('X-Timestamp');
    $ts = (int)$ts_header;
    if ($ts <= 0) nvd_fail(400, 'missing X-Timestamp');
    if (abs(time() - $ts) > (int)($config['timestamp_window_sec'] ?? 300)) nvd_fail(401, 'timestamp out of window (clock drift or replay?)');
    $sig = hash_hmac('sha256', $ts_header . '|' . $body, $expected);
    if (!hash_equals($sig, nvd_header('X-Signature'))) nvd_fail(401, 'invalid signature (tampered or wrong key)');

    if (nvd_counter($config, 'tenant_' . $tenant, 60) > NVD_TENANT_PER_MIN) nvd_fail(429, 'rate limit exceeded for this client');
    return [$tenant, $body];
}

/** What the agent may ask NVD: a fixed list of query parameters of the two search endpoints, nothing else (this script is not an open proxy). */
function nvd_build_query($kind, $params): array {
    $allowed = [
        'cves' => ['cveId', 'cpeName', 'keywordSearch', 'resultsPerPage', 'startIndex'],
        'cpes' => ['keywordSearch', 'resultsPerPage', 'startIndex'],
    ];
    if (!is_string($kind) || !isset($allowed[$kind]) || !is_array($params) || count($params) === 0) nvd_fail(400, 'bad request');
    $clean = [];
    foreach ($params as $k => $v) {
        if (!is_string($k) || !in_array($k, $allowed[$kind], true)) nvd_fail(400, 'parameter not allowed');
        if ($k === 'resultsPerPage') {
            $v = max(1, min(100, (int)$v));
        } elseif ($k === 'startIndex') {
            $v = max(0, min(10000, (int)$v));
        } else {
            if (!is_string($v) || $v === '' || strlen($v) > 300 || preg_match('/[\x00-\x1f\x7f]/', $v)) nvd_fail(400, 'bad value');
            if ($k === 'cveId') {
                $v = strtoupper($v);
                if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $v)) nvd_fail(400, 'bad cveId');
            }
            if ($k === 'cpeName' && strpos($v, 'cpe:2.3:') !== 0) nvd_fail(400, 'bad cpeName');
        }
        $clean[$k] = $v;
    }
    ksort($clean);
    return [$kind, $clean];
}

/** One request to NVD with the key. Returns [http status (0 = no answer), body]. */
function nvd_upstream(string $kind, array $clean, string $key): array {
    $url = NVD_BASE . $kind . '/2.0?' . http_build_query($clean, '', '&', PHP_QUERY_RFC3986);
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 25, CURLOPT_CONNECTTIMEOUT => 8, CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_HTTPHEADER => ['apiKey: ' . $key, 'User-Agent: MikroManager-Central/1', 'Accept: application/json'],
        ]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return [$code, $body === false ? '' : (string)$body];
    }
    $ctx = stream_context_create(['http' => [
        'method' => 'GET', 'timeout' => 25, 'ignore_errors' => true,
        'header' => "apiKey: $key\r\nUser-Agent: MikroManager-Central/1\r\nAccept: application/json\r\n",
    ]]);
    $body = @file_get_contents($url, false, $ctx);
    $code = 0;
    if (isset($http_response_header[0]) && preg_match('#HTTP/\S+\s+(\d+)#', (string)$http_response_header[0], $mm)) $code = (int)$mm[1];
    return [$code, $body === false ? '' : (string)$body];
}

/** Runs $fn holding one lock for all agents, no sooner than NVD_INTERVAL_US after the previous request to NVD; refuses (429) when the queue is too long. */
function nvd_throttled(array $config, callable $fn) {
    $dir = (string)($config['state_dir'] ?? (__DIR__ . '/state'));
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $fh = @fopen($dir . '/nvd_throttle', 'c+');
    if (!$fh) return $fn();
    $deadline = microtime(true) + NVD_MAX_WAIT_S;
    while (!flock($fh, LOCK_EX | LOCK_NB)) {
        if (microtime(true) > $deadline) {
            fclose($fh);
            nvd_fail(429, 'busy', ['retry_after' => 30]);
        }
        usleep(100000);
    }
    try {
        $last = (float)trim((string)stream_get_contents($fh));
        $wait = ($last + NVD_INTERVAL_US / 1000000) - microtime(true);
        if ($wait > 0) usleep((int)($wait * 1000000));
        return $fn();
    } finally {
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, sprintf('%.3f', microtime(true)));
        fflush($fh);
        flock($fh, LOCK_UN);
        fclose($fh);
    }
}

function nvd_count_use(PDO $pdo, string $tenant, bool $upstream): void {
    try {
        $pdo->prepare('INSERT INTO nvd_usage (usage_day, tenant, requests, upstream) VALUES (CURDATE(), ?, 1, ?)
                       ON DUPLICATE KEY UPDATE requests = requests + 1, upstream = upstream + VALUES(upstream)')
            ->execute([$tenant, $upstream ? 1 : 0]);
    } catch (Throwable $e) {
        // the statistics must never break a lookup
    }
}

function nvd_reply(string $json, string $cache): void {
    header('X-Nvd-Cache: ' . $cache);
    echo $json;
    exit;
}

function nvd_lookup(array $config): void {
    [$tenant, $body] = nvd_agent_auth($config);
    $req = json_decode($body, true);
    if (!is_array($req)) nvd_fail(400, 'bad json');
    [$kind, $clean] = nvd_build_query($req['kind'] ?? null, $req['params'] ?? null);

    $pdo = nvd_pdo($config);
    nvd_tables($pdo);
    $ckey = sha1($kind . '?' . http_build_query($clean));
    $ttl = isset($clean['cveId']) ? NVD_TTL_CVE : NVD_TTL_QUERY;
    $st = $pdo->prepare('SELECT body, TIMESTAMPDIFF(SECOND, fetched_at, NOW()) AS age FROM nvd_cache WHERE cache_key = ?');
    $st->execute([$ckey]);
    $hit = $st->fetch(PDO::FETCH_ASSOC);
    if ($hit && (int)$hit['age'] < $ttl) {
        nvd_count_use($pdo, $tenant, false);
        nvd_reply((string)$hit['body'], 'hit');
    }

    $key = nvd_get_key($pdo);
    if ($key === '') {
        if ($hit) nvd_reply((string)$hit['body'], 'stale');
        nvd_fail(503, 'no_key');
    }
    [$code, $resp] = nvd_throttled($config, function () use ($kind, $clean, $key) {
        return nvd_upstream($kind, $clean, $key);
    });
    $data = $code === 200 ? json_decode($resp, true) : null;
    if ($code === 200 && is_array($data)) {
        $pdo->prepare('REPLACE INTO nvd_cache (cache_key, body, fetched_at) VALUES (?, ?, NOW())')->execute([$ckey, $resp]);
        nvd_count_use($pdo, $tenant, true);
        if (random_int(0, 199) === 0) {
            $pdo->exec('DELETE FROM nvd_cache WHERE fetched_at < NOW() - INTERVAL 30 DAY');
        }
        nvd_reply($resp, 'miss');
    }
    if ($hit) {
        nvd_count_use($pdo, $tenant, false);
        nvd_reply((string)$hit['body'], 'stale');       // NVD is not answering: the older answer is better than none
    }
    nvd_fail(502, 'nvd_unavailable', ['http' => $code]);
}

/** A global administrator: a per-user session of role admin without a tenant scope, or the legacy shared viewer password (checked as api.php does).
 *  Failed attempts are counted per address; after a dozen in 15 minutes the address is refused for the rest of the window. */
function nvd_admin(PDO $pdo, array $config): array {
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    if (nvd_counter($config, 'adminfail_' . $ip, 900, false) > 12) nvd_fail(429, 'too many failed attempts');
    if (!preg_match('/Bearer\s+(.+)/i', nvd_header('Authorization'), $m)) {
        nvd_counter($config, 'adminfail_' . $ip, 900);
        nvd_fail(401, 'unauthorized');
    }
    $token = trim($m[1]);
    $st = $pdo->prepare('SELECT u.username, u.role, u.allowed_tenants, u.is_active FROM sessions s JOIN users u ON u.id = s.user_id
                         WHERE s.token_hash = ? AND s.expires_at > NOW()');
    $st->execute([hash('sha256', $token)]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    if ($row) {
        if (!(int)$row['is_active'] || $row['role'] !== 'admin' || $row['allowed_tenants'] !== null) nvd_fail(403, 'global_admin_required');
        return ['user' => (string)$row['username']];
    }
    if (hash_equals((string)($config['viewer_password'] ?? ''), $token)) {
        if (!empty($config['viewer_totp_secret'])) {
            require_once __DIR__ . '/totp.php';
            if (!totp_verify((string)$config['viewer_totp_secret'], nvd_header('X-Totp'))) {
                nvd_counter($config, 'adminfail_' . $ip, 900);
                nvd_fail(401, 'invalid or missing TOTP code');
            }
        }
        return ['user' => 'viewer'];
    }
    nvd_counter($config, 'adminfail_' . $ip, 900);
    nvd_fail(401, 'unauthorized');
    return [];
}

function nvd_status(PDO $pdo): array {
    $st = $pdo->prepare('SELECT updated_at, updated_by FROM central_settings WHERE name = ?');
    $st->execute(['nvd_api_key']);
    $meta = $st->fetch(PDO::FETCH_ASSOC) ?: [];
    $configured = nvd_get_key($pdo) !== '';
    $use = $pdo->query('SELECT tenant, SUM(requests) AS requests, SUM(upstream) AS upstream FROM nvd_usage
                        WHERE usage_day >= CURDATE() - INTERVAL 1 DAY GROUP BY tenant ORDER BY tenant')->fetchAll(PDO::FETCH_ASSOC);
    $cache = (int)$pdo->query('SELECT COUNT(*) FROM nvd_cache')->fetchColumn();
    return [
        'configured' => $configured,
        'updated_at' => $configured ? ($meta['updated_at'] ?? null) : null,
        'updated_by' => $configured ? ($meta['updated_by'] ?? null) : null,
        'usage' => array_map(function ($r) {
            return ['tenant' => $r['tenant'], 'requests' => (int)$r['requests'], 'upstream' => (int)$r['upstream']];
        }, $use),
        'cache_entries' => $cache,
    ];
}

try {
    $action = (string)($_GET['action'] ?? 'lookup');
    if ($action === 'lookup') {
        nvd_lookup($config);
    }
    $pdo = nvd_pdo($config);
    nvd_tables($pdo);
    $admin = nvd_admin($pdo, $config);
    if ($action === 'status') {
        echo json_encode(nvd_status($pdo));
    } elseif ($action === 'key_set' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
        $data = json_decode((string)file_get_contents('php://input'), true);
        $key = is_array($data) ? trim((string)($data['key'] ?? '')) : '';
        if (!preg_match('/^[A-Za-z0-9-]{16,64}$/', $key)) nvd_fail(400, 'that does not look like an NVD API key');
        [$code] = nvd_upstream('cves', ['cveId' => 'CVE-2021-44228'], $key);
        if ($code === 0) nvd_fail(502, 'NVD could not be reached from this server');
        if ($code !== 200) nvd_fail(400, 'NVD did not accept the key', ['http' => $code]);
        $pdo->prepare('INSERT INTO central_settings (name, value, updated_at, updated_by) VALUES (?, ?, NOW(), ?)
                       ON DUPLICATE KEY UPDATE value = VALUES(value), updated_at = NOW(), updated_by = VALUES(updated_by)')
            ->execute(['nvd_api_key', $key, $admin['user']]);
        echo json_encode(nvd_status($pdo));
    } elseif ($action === 'key_clear' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
        $pdo->prepare('DELETE FROM central_settings WHERE name = ?')->execute(['nvd_api_key']);
        echo json_encode(nvd_status($pdo));
    } else {
        nvd_fail(404, 'unknown action');
    }
} catch (Throwable $e) {
    error_log('[nvd.php] ' . get_class($e) . ': ' . $e->getMessage());
    nvd_fail(500, 'server error');
}
