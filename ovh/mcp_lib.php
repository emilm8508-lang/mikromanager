<?php
/**
 * MikroManager Central — shared code of the MCP connector (mcp.php) and its OAuth server (oauth.php).
 *
 * The connector lets the person's own Claude (claude.ai) or ChatGPT account read Central: they add Central as a custom connector,
 * sign in with their Central account (password + TOTP when it is on) and approve; from then on the model of their own subscription
 * can call the read-only tools of mcp.php, seeing exactly the clients (tenants) that account may see in Central.
 *
 * Standards (MCP authorization, 2025-11-25): OAuth 2.1 with PKCE (S256 only), Protected Resource Metadata (RFC 9728), Authorization
 * Server Metadata (RFC 8414) and OpenID discovery, client registration by Client ID Metadata Documents or Dynamic Client Registration
 * (RFC 7591), tokens bound to this MCP server (RFC 8707), refresh tokens rotated with reuse detection.
 *
 * The tables are created on first use (portable SQL: MySQL in production, SQLite in tests); no change to schema.sql is needed,
 * though the same statements are there for reference.
 */

declare(strict_types=1);

const MCP_ACCESS_TTL = 3600;              // 1 h
const MCP_REFRESH_TTL = 30 * 24 * 3600;   // 30 days, rotated on every use
const MCP_CODE_TTL = 600;                 // an authorization code lives 10 minutes
const MCP_SCOPE = 'read';
const MCP_VERSION = '1.0';

// Where a client may send the person back after signing in, unless config.php sets 'mcp_redirect_hosts': Claude's and ChatGPT's
// web callbacks; localhost is allowed too (Claude Desktop / Claude Code / MCP Inspector) but marked on the consent page.
const MCP_DEFAULT_REDIRECT_HOSTS = ['claude.ai', 'claude.com', 'chatgpt.com', 'chat.openai.com'];

function mcp_pdo(array $config): PDO {
    if (!empty($config['db']['dsn'])) {                                  // tests: sqlite
        $pdo = new PDO($config['db']['dsn']);
    } else {
        $dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', $config['db']['host'], $config['db']['name']);
        $pdo = new PDO($dsn, $config['db']['user'], $config['db']['password']);
    }
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    mcp_schema($pdo, $config);
    return $pdo;
}

function mcp_schema(PDO $pdo, array $config): void {
    $flag = rtrim((string)$config['state_dir'], '/\\') . '/mcp_schema_v1';
    if (is_file($flag)) return;
    $pdo->query('CREATE TABLE IF NOT EXISTS mcp_clients (
        client_id VARCHAR(191) NOT NULL PRIMARY KEY, secret_hash CHAR(64) NULL, name VARCHAR(200) NULL,
        redirect_uris TEXT NOT NULL, kind VARCHAR(8) NOT NULL, created INT NOT NULL, fetched INT NOT NULL DEFAULT 0, last_used INT NOT NULL DEFAULT 0)');
    $pdo->query('CREATE TABLE IF NOT EXISTS mcp_codes (
        code_hash CHAR(64) NOT NULL PRIMARY KEY, client_id VARCHAR(191) NOT NULL, user_id INT NOT NULL, redirect_uri TEXT NOT NULL,
        challenge VARCHAR(128) NOT NULL, resource VARCHAR(255) NOT NULL, scope VARCHAR(64) NOT NULL, exp INT NOT NULL, used INT NOT NULL DEFAULT 0,
        family CHAR(32) NOT NULL)');
    $pdo->query('CREATE TABLE IF NOT EXISTS mcp_tokens (
        token_hash CHAR(64) NOT NULL PRIMARY KEY, kind VARCHAR(8) NOT NULL, client_id VARCHAR(191) NOT NULL, user_id INT NOT NULL,
        resource VARCHAR(255) NOT NULL, scope VARCHAR(64) NOT NULL, family CHAR(32) NOT NULL, exp INT NOT NULL,
        revoked INT NOT NULL DEFAULT 0, created INT NOT NULL, last_used INT NOT NULL DEFAULT 0)');
    if (!is_dir(dirname($flag))) @mkdir(dirname($flag), 0700, true);
    @file_put_contents($flag, (string)time());
}

/** The public URL of the folder holding Central's scripts, e.g. https://example.com/mm (config 'public_base_url' wins). */
function mcp_base_url(array $config): string {
    if (!empty($config['public_base_url'])) return rtrim((string)$config['public_base_url'], '/');
    $host = (string)($_SERVER['HTTP_HOST'] ?? 'localhost');
    $local = (bool)preg_match('/^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/', $host);
    $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    $scheme = ($https || !$local) ? 'https' : 'http';                   // behind OVH's proxy HTTPS may not be visible: public = https
    $dir = rtrim(str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? '/'))), '/');
    return $scheme . '://' . $host . $dir;
}

function mcp_resource_url(array $config): string { return mcp_base_url($config) . '/mcp.php'; }
function mcp_issuer(array $config): string { return mcp_base_url($config) . '/oauth.php'; }

/** RFC 8707 resources compared the way the spec asks: scheme and host case-insensitive, no trailing slash. */
function mcp_same_resource(string $a, string $b): bool {
    $n = function (string $u): string {
        $p = parse_url(trim($u));
        if (!$p || empty($p['scheme']) || empty($p['host'])) return '';
        return strtolower($p['scheme']) . '://' . strtolower($p['host']) . (isset($p['port']) ? ':' . $p['port'] : '') . rtrim($p['path'] ?? '', '/');
    };
    return $n($a) !== '' && $n($a) === $n($b);
}

function mcp_json($data, int $status = 200, array $headers = []): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    foreach ($headers as $h) header($h);
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

function mcp_b64url(string $bin): string { return rtrim(strtr(base64_encode($bin), '+/', '-_'), '='); }

function mcp_auth_header(): string {
    foreach (['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'] as $k) {
        if (!empty($_SERVER[$k])) return (string)$_SERVER[$k];
    }
    if (function_exists('getallheaders')) {
        foreach (getallheaders() as $k => $v) { if (strcasecmp((string)$k, 'Authorization') === 0) return (string)$v; }
    }
    return '';
}

// ── Redirect / client host policy ────────────────────────────────────────────

function mcp_redirect_hosts(array $config): array {
    $h = $config['mcp_redirect_hosts'] ?? MCP_DEFAULT_REDIRECT_HOSTS;
    return array_map('strtolower', is_array($h) ? $h : MCP_DEFAULT_REDIRECT_HOSTS);
}

function mcp_is_local_host(string $host): bool {
    return in_array(strtolower($host), ['localhost', '127.0.0.1', '[::1]', '::1'], true);
}

/** A redirect URI may be https to an allowed host (or its subdomain), or http(s) to localhost. Fragments never. */
function mcp_redirect_ok(array $config, string $uri): bool {
    $p = parse_url($uri);
    if (!$p || empty($p['scheme']) || empty($p['host']) || isset($p['fragment'])) return false;
    $host = strtolower($p['host']);
    if (mcp_is_local_host($host)) return in_array($p['scheme'], ['http', 'https'], true);
    if ($p['scheme'] !== 'https') return false;
    foreach (mcp_redirect_hosts($config) as $allowed) {
        if ($host === $allowed || substr($host, -strlen('.' . $allowed)) === '.' . $allowed) return true;
    }
    return false;
}

// ── Clients ──────────────────────────────────────────────────────────────────

/** The client by id: a registered one (DCR), or a Client ID Metadata Document fetched from its https URL (cached a day). */
function mcp_client(PDO $pdo, array $config, string $client_id): ?array {
    if ($client_id === '' || strlen($client_id) > 191) return null;
    $st = $pdo->prepare('SELECT * FROM mcp_clients WHERE client_id = ?');
    $st->execute([$client_id]);
    $row = $st->fetch(PDO::FETCH_ASSOC) ?: null;
    $is_url = strncmp($client_id, 'https://', 8) === 0;
    if ($row && (!$is_url || (int)$row['fetched'] > time() - 86400)) {
        $row['redirect_uris'] = json_decode((string)$row['redirect_uris'], true) ?: [];
        return $row;
    }
    if (!$is_url) return null;
    $doc = mcp_fetch_client_document($config, $client_id);
    if (!$doc) return null;
    $uris = json_encode(array_values($doc['redirect_uris']));
    $pdo->prepare('DELETE FROM mcp_clients WHERE client_id = ?')->execute([$client_id]);
    $pdo->prepare('INSERT INTO mcp_clients (client_id, secret_hash, name, redirect_uris, kind, created, fetched) VALUES (?, NULL, ?, ?, ?, ?, ?)')
        ->execute([$client_id, mb_substr((string)($doc['client_name'] ?? ''), 0, 200), $uris, 'cimd', time(), time()]);
    return ['client_id' => $client_id, 'secret_hash' => null, 'name' => $doc['client_name'] ?? null, 'redirect_uris' => $doc['redirect_uris'], 'kind' => 'cimd'];
}

/** Fetches a Client ID Metadata Document - only from an allowed client host (no requests to arbitrary addresses), no redirects, 64 KB at most. */
function mcp_fetch_client_document(array $config, string $url): ?array {
    $p = parse_url($url);
    if (!$p || ($p['scheme'] ?? '') !== 'https' || empty($p['host']) || empty($p['path']) || $p['path'] === '/') return null;
    $host = strtolower($p['host']);
    $ok = false;
    foreach (mcp_redirect_hosts($config) as $allowed) {
        if ($host === $allowed || substr($host, -strlen('.' . $allowed)) === '.' . $allowed) { $ok = true; break; }
    }
    if (!$ok || !function_exists('curl_init')) return null;
    $ch = curl_init($url);
    $body = '';
    curl_setopt_array($ch, [
        CURLOPT_FOLLOWLOCATION => false, CURLOPT_TIMEOUT => 6, CURLOPT_CONNECTTIMEOUT => 4, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_HTTPHEADER => ['Accept: application/json'],
        CURLOPT_WRITEFUNCTION => function ($ch, $chunk) use (&$body) { $body .= $chunk; return strlen($body) > 65536 ? 0 : strlen($chunk); },
    ]);
    curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($code !== 200 || strlen($body) > 65536) return null;
    $doc = json_decode($body, true);
    if (!is_array($doc) || ($doc['client_id'] ?? null) !== $url || !is_array($doc['redirect_uris'] ?? null) || !$doc['redirect_uris']) return null;
    foreach ($doc['redirect_uris'] as $u) { if (!is_string($u)) return null; }
    return $doc;
}

// ── Tokens ───────────────────────────────────────────────────────────────────

function mcp_issue_tokens(PDO $pdo, string $client_id, int $user_id, string $resource, string $scope, string $family): array {
    $access = 'mma_' . bin2hex(random_bytes(32));
    $refresh = 'mmr_' . bin2hex(random_bytes(32));
    $now = time();
    $ins = $pdo->prepare('INSERT INTO mcp_tokens (token_hash, kind, client_id, user_id, resource, scope, family, exp, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
    $ins->execute([hash('sha256', $access), 'access', $client_id, $user_id, $resource, $scope, $family, $now + MCP_ACCESS_TTL, $now]);
    $ins->execute([hash('sha256', $refresh), 'refresh', $client_id, $user_id, $resource, $scope, $family, $now + MCP_REFRESH_TTL, $now]);
    $pdo->prepare('UPDATE mcp_clients SET last_used = ? WHERE client_id = ?')->execute([$now, $client_id]);
    if (mt_rand(1, 50) === 1) {                                           // housekeeping without cron
        $pdo->prepare('DELETE FROM mcp_tokens WHERE exp < ?')->execute([$now - 86400]);
        $pdo->prepare('DELETE FROM mcp_codes WHERE exp < ?')->execute([$now - 86400]);
        $pdo->prepare("DELETE FROM mcp_clients WHERE kind = 'dcr' AND last_used < ? AND created < ?")->execute([$now - 90 * 86400, $now - 86400]);
    }
    return ['access_token' => $access, 'token_type' => 'Bearer', 'expires_in' => MCP_ACCESS_TTL, 'refresh_token' => $refresh, 'scope' => $scope];
}

function mcp_revoke_family(PDO $pdo, string $family): void {
    $pdo->prepare('UPDATE mcp_tokens SET revoked = 1 WHERE family = ?')->execute([$family]);
}

/** The Central user behind a live access token for this MCP server, or null. */
function mcp_identity(PDO $pdo, array $config, string $token): ?array {
    if (strncmp($token, 'mma_', 4) !== 0) return null;
    $st = $pdo->prepare("SELECT t.user_id, t.resource, t.client_id, t.last_used, t.token_hash, u.username, u.role, u.allowed_tenants, u.is_active
                         FROM mcp_tokens t JOIN users u ON u.id = t.user_id
                         WHERE t.token_hash = ? AND t.kind = 'access' AND t.revoked = 0 AND t.exp > ?");
    $st->execute([hash('sha256', $token), time()]);
    $r = $st->fetch(PDO::FETCH_ASSOC);
    if (!$r || !(int)$r['is_active'] || !mcp_same_resource((string)$r['resource'], mcp_resource_url($config))) return null;
    if ((int)$r['last_used'] < time() - 60) {
        $pdo->prepare('UPDATE mcp_tokens SET last_used = ? WHERE token_hash = ?')->execute([time(), $r['token_hash']]);
    }
    $allowed = $r['allowed_tenants'] !== null ? (json_decode((string)$r['allowed_tenants'], true) ?: []) : null;
    return ['id' => (int)$r['user_id'], 'username' => $r['username'], 'role' => $r['role'], 'allowed_tenants' => $allowed, 'client_id' => $r['client_id']];
}

// ── Sign-in lockout: the same files as api.php's per-user login, so failures count together ──

function mcp_lockout_path(array $config, string $username): string {
    $dir = (string)$config['state_dir'];
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    return $dir . '/user_login_fail_' . preg_replace('/[^a-zA-Z0-9_.-]/', '_', strtolower($username)) . '.json';
}

function mcp_locked_for(array $config, string $username): int {
    $path = mcp_lockout_path($config, $username);
    if (!is_file($path)) return 0;
    $d = json_decode((string)file_get_contents($path), true);
    $until = is_array($d) ? (int)($d['locked_until'] ?? 0) : 0;
    return max(0, $until - time());
}

function mcp_lockout_record(array $config, string $username, bool $success): void {
    $path = mcp_lockout_path($config, $username);
    if ($success) { @unlink($path); return; }
    $d = is_file($path) ? json_decode((string)file_get_contents($path), true) : null;
    $count = (is_array($d) ? (int)($d['count'] ?? 0) : 0) + 1;
    $sec = $count >= 15 ? 1800 : ($count >= 10 ? 300 : ($count >= 5 ? 60 : 0));
    file_put_contents($path, json_encode(['count' => $count, 'locked_until' => $sec ? time() + $sec : 0]), LOCK_EX);
}
