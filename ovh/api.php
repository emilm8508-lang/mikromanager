<?php
/**
 * MikroManager central — viewer API.
 *
 * Auth (two paths, tried in this order on every request except
 * `login`/`logout` which are unauthenticated/self-authenticated):
 *   1. Authorization: Bearer <per-user session token> — issued by
 *      ?action=login (see `users`/`sessions` tables); the identity carries
 *      a role (admin/viewer) and an allowed_tenants scope (null = all).
 *   2. Authorization: Bearer <viewer_password> (+ optional X-Totp) — the
 *      original single shared secret, kept working as a full-access
 *      legacy fallback so existing deployments don't break.
 *
 * Endpoints (selected by ?action=):
 *   ?action=login              → POST {username,password,totp_code?,tenant?}, returns a session token
 *   ?action=tenants            → list tenants the caller may see + online status
 *   ?action=snapshot&tenant=X  → latest snapshot for tenant X
 *   ?action=history&tenant=X   → list of recent received_at timestamps (last 50)
 */

declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Authorization, Content-Type, X-Totp');
header('Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS');

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$config = require __DIR__ . '/config.php';
require_once __DIR__ . '/notifications.php';
require_once __DIR__ . '/totp.php';
require_once __DIR__ . '/anydesk.php';

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

function get_totp_header(): string {
    if (!empty($_SERVER['HTTP_X_TOTP'])) return $_SERVER['HTTP_X_TOTP'];
    if (function_exists('getallheaders')) {
        foreach (getallheaders() as $k => $v) {
            if (strcasecmp($k, 'X-Totp') === 0) return $v;
        }
    }
    return '';
}

// Login lockout — file-based (one JSON file per client IP in state_dir,
// same convention as the ingest.php rate limiter), since PHP has no
// persistent process to hold this in memory like the local agent's login
// throttle (backend/services/auth.py) does. Escalating: 5 fails → 60s,
// 10 → 5 min, 15+ → 30 min. Applies regardless of whether TOTP is
// configured — it's the universal protection for the shared password.
function _login_lockout_path(array $config, string $ip): string {
    $dir = $config['state_dir'];
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    return $dir . '/login_fail_' . preg_replace('/[^a-zA-Z0-9_.:]/', '_', $ip) . '.json';
}

function login_lockout_check(array $config, string $ip): void {
    $path = _login_lockout_path($config, $ip);
    if (!is_file($path)) return;
    $data = json_decode((string)file_get_contents($path), true);
    $locked_until = is_array($data) ? (int)($data['locked_until'] ?? 0) : 0;
    if ($locked_until > time()) {
        http_response_code(429);
        echo json_encode(['error' => 'too many failed attempts', 'retry_after_sec' => $locked_until - time()]);
        exit;
    }
}

function login_lockout_record(array $config, string $ip, bool $success): void {
    $path = _login_lockout_path($config, $ip);
    if ($success) {
        @unlink($path);
        return;
    }
    $data = is_file($path) ? json_decode((string)file_get_contents($path), true) : null;
    $count = (is_array($data) ? (int)($data['count'] ?? 0) : 0) + 1;
    $lockout_sec = $count >= 15 ? 1800 : ($count >= 10 ? 300 : ($count >= 5 ? 60 : 0));
    $next = ['count' => $count, 'locked_until' => $lockout_sec ? time() + $lockout_sec : 0];
    file_put_contents($path, json_encode($next), LOCK_EX);
}

// ── Per-user accounts (multi-user, OVH-primary auth) ───────────────────────
// Same file-based lockout convention as above, keyed by username instead of
// IP (this is now a real login form, not just "do you know the shared
// password") — PHP-FPM has no persistent process, hence files not memory,
// same reasoning as the local agent's in-memory throttle can't be reused here.
function _user_login_lockout_path(array $config, string $username): string {
    $dir = $config['state_dir'];
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    return $dir . '/user_login_fail_' . preg_replace('/[^a-zA-Z0-9_.-]/', '_', strtolower($username)) . '.json';
}

function user_login_lockout_check(array $config, string $username): void {
    $path = _user_login_lockout_path($config, $username);
    if (!is_file($path)) return;
    $data = json_decode((string)file_get_contents($path), true);
    $locked_until = is_array($data) ? (int)($data['locked_until'] ?? 0) : 0;
    if ($locked_until > time()) {
        http_response_code(429);
        echo json_encode(['error' => 'too_many_attempts', 'retry_after_sec' => $locked_until - time()]);
        exit;
    }
}

function user_login_lockout_record(array $config, string $username, bool $success): void {
    $path = _user_login_lockout_path($config, $username);
    if ($success) {
        @unlink($path);
        return;
    }
    $data = is_file($path) ? json_decode((string)file_get_contents($path), true) : null;
    $count = (is_array($data) ? (int)($data['count'] ?? 0) : 0) + 1;
    $lockout_sec = $count >= 15 ? 1800 : ($count >= 10 ? 300 : ($count >= 5 ? 60 : 0));
    $next = ['count' => $count, 'locked_until' => $lockout_sec ? time() + $lockout_sec : 0];
    file_put_contents($path, json_encode($next), LOCK_EX);
}

/** Occasionally sweep expired sessions — same 1% probabilistic pattern as
 * ingest.php's rate-limit file pruning, avoids a cron dependency. Named
 * mm_ (not session_gc) — session_gc() collides with PHP's OWN built-in
 * function of that name (session extension) and causes a fatal
 * "Cannot redeclare" error that kills the entire script. */
function mm_session_gc(PDO $pdo): void {
    if (mt_rand(1, 100) === 1) {
        try { $pdo->exec('DELETE FROM sessions WHERE expires_at < NOW()'); } catch (Throwable $e) {}
    }
}

function bearer_token(): string {
    return trim((string)preg_replace('/Bearer\s+/i', '', get_auth_header(), 1));
}

/** Resolve a bearer token as a live per-user session. Returns
 * {id, username, role, allowed_tenants} (allowed_tenants: array or null =
 * all tenants) or null if the token doesn't match any live, active-user
 * session — NOT an error by itself, callers decide (session vs legacy path). */
function resolve_user_session(PDO $pdo, string $token): ?array {
    if ($token === '') return null;
    $hash = hash('sha256', $token);
    $stmt = $pdo->prepare(
        'SELECT u.id, u.username, u.role, u.allowed_tenants, u.is_active, s.id AS session_id
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ? AND s.expires_at > NOW()'
    );
    $stmt->execute([$hash]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row || !(int)$row['is_active']) return null;
    $pdo->prepare('UPDATE sessions SET last_seen_at = NOW() WHERE id = ?')->execute([$row['session_id']]);
    $allowed = $row['allowed_tenants'] !== null ? (json_decode($row['allowed_tenants'], true) ?: []) : null;
    return ['id' => (int)$row['id'], 'username' => $row['username'], 'role' => $row['role'], 'allowed_tenants' => $allowed];
}

function require_user_session(PDO $pdo, string $token): array {
    $u = resolve_user_session($pdo, $token);
    if (!$u) {
        http_response_code(401);
        echo json_encode(['error' => 'invalid_or_expired_session']);
        exit;
    }
    return $u;
}

/** Only a GLOBAL admin (role=admin AND allowed_tenants=NULL) may manage
 * accounts — a tenant-scoped admin can run their own tenant's devices/
 * rules, but must not be able to create/escalate other users. */
function require_admin_session(PDO $pdo, string $token): array {
    $u = require_user_session($pdo, $token);
    if ($u['role'] !== 'admin' || $u['allowed_tenants'] !== null) {
        http_response_code(403);
        echo json_encode(['error' => 'global_admin_required']);
        exit;
    }
    return $u;
}

/** True if $identity may see/act on $tenant. allowed_tenants=NULL (legacy
 * shared-password identity, or a global per-user account) means "all". */
function tenant_allowed(array $identity, string $tenant): bool {
    if ($identity['allowed_tenants'] === null) return true;
    return in_array($tenant, $identity['allowed_tenants'], true);
}

function require_tenant(array $identity, string $tenant): void {
    if (!tenant_allowed($identity, $tenant)) {
        http_response_code(403);
        echo json_encode(['error' => 'tenant_not_allowed']);
        exit;
    }
}

/** For actions that are inherently cross-tenant (global config, storage
 * usage, account management) — only a global-scoped identity may use them;
 * a tenant-scoped admin manages their own tenant's data, not the server. */
function require_global(array $identity): void {
    if ($identity['allowed_tenants'] !== null) {
        http_response_code(403);
        echo json_encode(['error' => 'global_scope_required']);
        exit;
    }
}

function require_write(array $identity): void {
    if ($identity['role'] !== 'admin') {
        http_response_code(403);
        echo json_encode(['error' => 'admin_role_required']);
        exit;
    }
}

$client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

// ── Routing ──────────────────────────────────────────────────────────────────
$action = $_GET['action'] ?? 'tenants';
$threshold = (int)($config['offline_threshold_sec'] ?? 300);
$user_auth_actions = [
    'login', 'logout', 'me', 'me_totp_confirm', 'users_list', 'user_add', 'user_update', 'user_delete', 'user_totp_reset',
    'anydesk_status', 'anydesk_sync_now', 'anydesk_import_csv', 'anydesk_client_map_list', 'anydesk_client_map_add', 'anydesk_client_map_delete',
    'anydesk_sessions', 'anydesk_session_classify', 'anydesk_summary', 'anydesk_unassigned',
];

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
    mm_session_gc($pdo);

    if (in_array($action, $user_auth_actions, true)) {
        // ── New: per-user login/account-management actions. Own auth
        // (a session token, or none at all for `login` itself) — these
        // deliberately bypass the legacy viewer_password gate below.
        switch ($action) {

            case 'login':
                $data = json_decode((string)file_get_contents('php://input'), true);
                if (!is_array($data)) $data = [];
                $username = trim((string)($data['username'] ?? ''));
                $password = (string)($data['password'] ?? '');
                $totp_code = (string)($data['totp_code'] ?? '');
                $req_tenant = trim((string)($data['tenant'] ?? ''));
                if ($username === '' || $password === '') {
                    http_response_code(400);
                    echo json_encode(['error' => 'username and password required']);
                    break;
                }
                user_login_lockout_check($config, $username);
                $stmt = $pdo->prepare('SELECT * FROM users WHERE username = ? AND is_active = 1');
                $stmt->execute([$username]);
                $row = $stmt->fetch(PDO::FETCH_ASSOC);
                if (!$row) {
                    // Distinguish "nobody has been provisioned yet" (agent
                    // may auto-fallback to its local emergency account) from
                    // a genuine bad username (must NOT auto-fallback).
                    $total = (int)$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
                    if ($total === 0) {
                        http_response_code(404);
                        echo json_encode(['error' => 'not_provisioned']);
                        break;
                    }
                    user_login_lockout_record($config, $username, false);
                    http_response_code(401);
                    echo json_encode(['error' => 'invalid_credentials']);
                    break;
                }
                $ok = password_verify($password, (string)$row['password_hash']);
                if ($ok && (int)$row['totp_enabled'] === 1) {
                    $ok = totp_verify((string)$row['totp_secret'], $totp_code);
                }
                if (!$ok) {
                    user_login_lockout_record($config, $username, false);
                    http_response_code(401);
                    echo json_encode(['error' => 'invalid_credentials']);
                    break;
                }
                $allowed = $row['allowed_tenants'] !== null ? (json_decode($row['allowed_tenants'], true) ?: []) : null;
                if ($req_tenant !== '' && $allowed !== null && !in_array($req_tenant, $allowed, true)) {
                    // Valid credentials, but this account isn't scoped to the
                    // agent that's asking — reject distinctly, no fallback
                    // (the operator can still deliberately use the local
                    // emergency account, which needs its own credentials anyway).
                    // Not a lockout-counted failure: the password/TOTP were
                    // correct, this is a scope mismatch, not a guessing attempt.
                    http_response_code(403);
                    echo json_encode(['error' => 'tenant_not_allowed']);
                    break;
                }
                user_login_lockout_record($config, $username, true);
                $token = bin2hex(random_bytes(32));
                $ttl = (int)($config['user_session_ttl_sec'] ?? 7 * 24 * 3600);
                $pdo->prepare('INSERT INTO sessions (user_id, token_hash, expires_at, ip) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND), ?)')
                    ->execute([(int)$row['id'], hash('sha256', $token), $ttl, $client_ip]);
                $pdo->prepare('UPDATE users SET last_login_at = NOW() WHERE id = ?')->execute([(int)$row['id']]);
                echo json_encode([
                    'token' => $token, 'username' => $row['username'], 'role' => $row['role'],
                    'allowed_tenants' => $allowed, 'expires_at' => date('c', time() + $ttl),
                ]);
                break;

            case 'logout':
                $tok = bearer_token();
                if ($tok !== '') {
                    $pdo->prepare('DELETE FROM sessions WHERE token_hash = ?')->execute([hash('sha256', $tok)]);
                }
                echo json_encode(['ok' => true]);
                break;

            case 'me':
                $u = require_user_session($pdo, bearer_token());
                echo json_encode($u);
                break;

            case 'me_totp_confirm':
                $u = require_user_session($pdo, bearer_token());
                $data = json_decode((string)file_get_contents('php://input'), true);
                if (!is_array($data)) $data = [];
                $code = (string)($data['code'] ?? '');
                $stmt = $pdo->prepare('SELECT totp_secret FROM users WHERE id = ?');
                $stmt->execute([$u['id']]);
                $secret = (string)$stmt->fetchColumn();
                if ($secret === '' || !totp_verify($secret, $code)) {
                    http_response_code(400);
                    echo json_encode(['error' => 'invalid_code']);
                    break;
                }
                $pdo->prepare('UPDATE users SET totp_enabled = 1 WHERE id = ?')->execute([$u['id']]);
                echo json_encode(['ok' => true]);
                break;

            case 'users_list':
                require_admin_session($pdo, bearer_token());
                $rows = $pdo->query('SELECT id, username, role, allowed_tenants, totp_enabled, is_active, created_at, last_login_at FROM users ORDER BY username')->fetchAll(PDO::FETCH_ASSOC);
                foreach ($rows as &$r) {
                    $r['allowed_tenants'] = $r['allowed_tenants'] !== null ? (json_decode($r['allowed_tenants'], true) ?: []) : null;
                    $r['totp_enabled'] = (int)$r['totp_enabled'];
                    $r['is_active'] = (int)$r['is_active'];
                }
                echo json_encode(['users' => $rows]);
                break;

            case 'user_add':
                // Bootstrap: while the users table is completely empty, allow
                // creating the FIRST account without an existing session —
                // otherwise this is unreachable (user_add needs an admin
                // session, but no session can exist until a user exists).
                // Mirrors the local agent's own POST /auth/setup, which is
                // likewise open exactly until the first (and only) local
                // account is created. The bootstrap account is always forced
                // to global admin, regardless of what role/allowed_tenants
                // were submitted — no ambiguity about whether the very first
                // account can manage the rest.
                $is_bootstrap = (int)$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn() === 0;
                if (!$is_bootstrap) {
                    require_admin_session($pdo, bearer_token());
                }
                $data = json_decode((string)file_get_contents('php://input'), true);
                if (!is_array($data)) $data = [];
                $username = trim((string)($data['username'] ?? ''));
                $password = (string)($data['password'] ?? '');
                $role = $is_bootstrap ? 'admin' : (string)($data['role'] ?? 'viewer');
                $allowed = $is_bootstrap ? null : (array_key_exists('allowed_tenants', $data) ? $data['allowed_tenants'] : null);
                if ($username === '' || strlen($password) < 8 || !in_array($role, ['admin', 'viewer'], true)) {
                    http_response_code(400);
                    echo json_encode(['error' => 'username, password (>=8 chars) and a valid role are required']);
                    break;
                }
                if ($allowed !== null && !is_array($allowed)) {
                    http_response_code(400);
                    echo json_encode(['error' => 'allowed_tenants must be an array or null']);
                    break;
                }
                try {
                    $stmt = $pdo->prepare('INSERT INTO users (username, password_hash, role, allowed_tenants, totp_enabled) VALUES (?, ?, ?, ?, 0)');
                    $stmt->execute([
                        $username,
                        password_hash($password, PASSWORD_DEFAULT),
                        $role,
                        $allowed !== null ? json_encode(array_values(array_map('strval', $allowed))) : null,
                    ]);
                } catch (PDOException $e) {
                    http_response_code(409);
                    echo json_encode(['error' => 'username already exists']);
                    break;
                }
                echo json_encode(['ok' => true, 'id' => (int)$pdo->lastInsertId()]);
                break;

            case 'user_update':
                require_admin_session($pdo, bearer_token());
                $data = json_decode((string)file_get_contents('php://input'), true);
                if (!is_array($data)) $data = [];
                $id = (int)($data['id'] ?? 0);
                if ($id <= 0) {
                    http_response_code(400);
                    echo json_encode(['error' => 'id required']);
                    break;
                }
                $demoting = array_key_exists('role', $data) && $data['role'] !== 'admin';
                $deactivating = array_key_exists('is_active', $data) && !$data['is_active'];
                $rescoping = array_key_exists('allowed_tenants', $data) && $data['allowed_tenants'] !== null;
                if ($demoting || $deactivating || $rescoping) {
                    $stmt2 = $pdo->prepare('SELECT role, allowed_tenants, is_active FROM users WHERE id = ?');
                    $stmt2->execute([$id]);
                    $target = $stmt2->fetch(PDO::FETCH_ASSOC);
                    $target_is_last_admin = $target && $target['role'] === 'admin' && $target['allowed_tenants'] === null && (int)$target['is_active'] === 1;
                    if ($target_is_last_admin) {
                        $stmt3 = $pdo->prepare("SELECT COUNT(*) FROM users WHERE role='admin' AND allowed_tenants IS NULL AND is_active=1 AND id<>?");
                        $stmt3->execute([$id]);
                        if ((int)$stmt3->fetchColumn() === 0) {
                            http_response_code(400);
                            echo json_encode(['error' => 'cannot demote, rescope, or deactivate the last global admin']);
                            break;
                        }
                    }
                }
                $sets = []; $vals = [];
                if (array_key_exists('role', $data)) {
                    if (!in_array($data['role'], ['admin', 'viewer'], true)) {
                        http_response_code(400);
                        echo json_encode(['error' => 'invalid role']);
                        break;
                    }
                    $sets[] = 'role=?'; $vals[] = $data['role'];
                }
                if (array_key_exists('allowed_tenants', $data)) {
                    $a = $data['allowed_tenants'];
                    if ($a !== null && !is_array($a)) {
                        http_response_code(400);
                        echo json_encode(['error' => 'allowed_tenants must be an array or null']);
                        break;
                    }
                    $sets[] = 'allowed_tenants=?'; $vals[] = $a !== null ? json_encode(array_values(array_map('strval', $a))) : null;
                }
                if (array_key_exists('is_active', $data)) { $sets[] = 'is_active=?'; $vals[] = $data['is_active'] ? 1 : 0; }
                if (array_key_exists('password', $data) && $data['password'] !== '') {
                    if (strlen((string)$data['password']) < 8) {
                        http_response_code(400);
                        echo json_encode(['error' => 'password too short']);
                        break;
                    }
                    $sets[] = 'password_hash=?'; $vals[] = password_hash((string)$data['password'], PASSWORD_DEFAULT);
                }
                if (empty($sets)) { echo json_encode(['ok' => true, 'no_changes' => true]); break; }
                $vals[] = $id;
                $pdo->prepare('UPDATE users SET ' . implode(',', $sets) . ' WHERE id=?')->execute($vals);
                if ($deactivating) {
                    $pdo->prepare('DELETE FROM sessions WHERE user_id = ?')->execute([$id]);
                }
                echo json_encode(['ok' => true]);
                break;

            case 'user_delete':
                require_admin_session($pdo, bearer_token());
                $id = (int)($_GET['id'] ?? 0);
                if ($id <= 0) {
                    http_response_code(400);
                    echo json_encode(['error' => 'id required']);
                    break;
                }
                $stmt2 = $pdo->prepare('SELECT role, allowed_tenants FROM users WHERE id = ? AND is_active = 1');
                $stmt2->execute([$id]);
                $target = $stmt2->fetch(PDO::FETCH_ASSOC);
                if ($target && $target['role'] === 'admin' && $target['allowed_tenants'] === null) {
                    $stmt3 = $pdo->prepare("SELECT COUNT(*) FROM users WHERE role='admin' AND allowed_tenants IS NULL AND is_active=1 AND id<>?");
                    $stmt3->execute([$id]);
                    if ((int)$stmt3->fetchColumn() === 0) {
                        http_response_code(400);
                        echo json_encode(['error' => 'cannot delete the last global admin']);
                        break;
                    }
                }
                $pdo->prepare('DELETE FROM sessions WHERE user_id = ?')->execute([$id]);
                $stmt = $pdo->prepare('DELETE FROM users WHERE id = ?');
                $stmt->execute([$id]);
                echo json_encode(['ok' => true, 'deleted' => $stmt->rowCount()]);
                break;

            case 'user_totp_reset':
                require_admin_session($pdo, bearer_token());
                $id = (int)($_GET['id'] ?? 0);
                if ($id <= 0) {
                    http_response_code(400);
                    echo json_encode(['error' => 'id required']);
                    break;
                }
                $stmt = $pdo->prepare('SELECT username FROM users WHERE id = ?');
                $stmt->execute([$id]);
                $username = $stmt->fetchColumn();
                if (!$username) {
                    http_response_code(404);
                    echo json_encode(['error' => 'not found']);
                    break;
                }
                $secret = totp_generate_secret();
                $pdo->prepare('UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?')->execute([$secret, $id]);
                echo json_encode(['secret' => $secret, 'otpauth_uri' => totp_provisioning_uri($secret, (string)$username)]);
                break;

            // ── AnyDesk time tracking — global-admin only, entirely separate
            // from tenant-scoped accounts (this is the consultant's own
            // billing data, never exposed to a client's own login). ────────

            case 'anydesk_status':
                require_admin_session($pdo, bearer_token());
                anydesk_maybe_sync($pdo, $config);
                $state = anydesk_sync_state($config);
                $total = (int)$pdo->query('SELECT COUNT(*) FROM anydesk_sessions')->fetchColumn();
                $unclassified = (int)$pdo->query('SELECT COUNT(*) FROM anydesk_sessions WHERE category IS NULL')->fetchColumn();
                $unassigned = (int)$pdo->query('SELECT COUNT(*) FROM anydesk_sessions WHERE tenant IS NULL')->fetchColumn();
                echo json_encode([
                    'configured' => $config['anydesk_license_id'] !== '' && $config['anydesk_api_key'] !== '',
                    'last_sync_at' => $state['last_sync_at'],
                    'last_error' => $state['last_error'],
                    'sessions_total' => $total,
                    'sessions_unclassified' => $unclassified,
                    'sessions_unassigned' => $unassigned,
                ]);
                break;

            case 'anydesk_unassigned':
                // Distinct not-yet-mapped remote clients (grouped, not one
                // row per session) — feeds the "Przypisz nieprzypisane"
                // review flow: assign a tenant once per unique cid instead
                // of hunting through the full session list one row at a
                // time. Grouped by to_cid only (the client side of an
                // operator-initiated outbound connection, the dominant
                // case) — an inbound session where the client is from_cid
                // instead is a known, unhandled edge case for now.
                require_admin_session($pdo, bearer_token());
                $rows = $pdo->query(
                    'SELECT to_cid AS cid, MAX(to_alias) AS alias, COUNT(*) AS session_count, MAX(start_time) AS last_seen
                     FROM anydesk_sessions
                     WHERE tenant IS NULL
                     GROUP BY to_cid
                     ORDER BY session_count DESC, last_seen DESC'
                )->fetchAll(PDO::FETCH_ASSOC);
                echo json_encode(['unassigned' => $rows]);
                break;

            case 'anydesk_sync_now':
                require_admin_session($pdo, bearer_token());
                echo json_encode(anydesk_sync($pdo, $config));
                break;

            case 'anydesk_import_csv':
                // Works on ANY AnyDesk license (no API key needed) — the
                // manual alternative to anydesk_sync_now for accounts below
                // the Standard tier, which doesn't include the REST-API.
                require_admin_session($pdo, bearer_token());
                $data = json_decode((string)file_get_contents('php://input'), true);
                if (!is_array($data)) $data = [];
                $csv = (string)($data['csv'] ?? '');
                if ($csv === '') {
                    http_response_code(400);
                    echo json_encode(['error' => 'csv required']);
                    break;
                }
                if (strlen($csv) > 5 * 1024 * 1024) {
                    http_response_code(413);
                    echo json_encode(['error' => 'csv too large (max 5MB)']);
                    break;
                }
                $parsed = anydesk_parse_csv_content($csv);
                if ($parsed['error'] !== null) {
                    http_response_code(400);
                    echo json_encode(['error' => $parsed['error']]);
                    break;
                }
                echo json_encode(anydesk_import_csv_rows($pdo, $parsed['rows']));
                break;

            case 'anydesk_client_map_list':
                require_admin_session($pdo, bearer_token());
                $rows = $pdo->query('SELECT id, tenant, anydesk_cid, label, created_at FROM anydesk_client_map ORDER BY tenant, anydesk_cid')->fetchAll(PDO::FETCH_ASSOC);
                echo json_encode(['mappings' => $rows]);
                break;

            case 'anydesk_client_map_add':
                require_admin_session($pdo, bearer_token());
                $data = json_decode((string)file_get_contents('php://input'), true);
                if (!is_array($data)) $data = [];
                $tenant = trim((string)($data['tenant'] ?? ''));
                $cid = anydesk_normalize_cid($data['anydesk_cid'] ?? '');
                $label = trim((string)($data['label'] ?? '')) ?: null;
                // Deliberately NOT restricted to $config['tenants'] (agents
                // with a configured api_key) — AnyDesk time tracking covers
                // any billing client, including ones with no MikroManager
                // agent at all. This is its own free-text client namespace.
                if ($tenant === '' || strlen($tenant) > 64) {
                    http_response_code(400);
                    echo json_encode(['error' => 'tenant (client name) required, max 64 chars']);
                    break;
                }
                if ($cid === '') {
                    http_response_code(400);
                    echo json_encode(['error' => 'anydesk_cid required (digits only)']);
                    break;
                }
                try {
                    $stmt = $pdo->prepare('INSERT INTO anydesk_client_map (tenant, anydesk_cid, label) VALUES (?, ?, ?)');
                    $stmt->execute([$tenant, $cid, $label]);
                } catch (PDOException $e) {
                    http_response_code(409);
                    echo json_encode(['error' => 'this AnyDesk ID is already mapped']);
                    break;
                }
                // Retroactively fix sessions imported/synced BEFORE this
                // mapping existed — without this, a mapping added after the
                // fact only applies to future syncs, and already-unassigned
                // sessions stay stuck as unassigned forever. Compared in PHP
                // (not SQL "= ?") so a row whose from_cid/to_cid was stored
                // BEFORE anydesk_normalize_cid() existed (stray whitespace
                // etc. never stripped) still matches correctly — this must
                // keep working without ever needing a re-import/re-sync,
                // since the source file may no longer be available later.
                $candidates = $pdo->query('SELECT id, from_cid, to_cid FROM anydesk_sessions WHERE tenant IS NULL')->fetchAll(PDO::FETCH_ASSOC);
                $fixIds = [];
                foreach ($candidates as $row) {
                    if (anydesk_normalize_cid($row['from_cid']) === $cid || anydesk_normalize_cid($row['to_cid']) === $cid) {
                        $fixIds[] = (int)$row['id'];
                    }
                }
                $retroCount = 0;
                if (!empty($fixIds)) {
                    $placeholders = implode(',', array_fill(0, count($fixIds), '?'));
                    $upd = $pdo->prepare("UPDATE anydesk_sessions SET tenant = ? WHERE id IN ({$placeholders})");
                    $upd->execute(array_merge([$tenant], $fixIds));
                    $retroCount = $upd->rowCount();
                }
                echo json_encode(['ok' => true, 'id' => (int)$pdo->lastInsertId(), 'retroactively_assigned' => $retroCount]);
                break;

            case 'anydesk_client_map_delete':
                require_admin_session($pdo, bearer_token());
                $id = (int)($_GET['id'] ?? 0);
                if ($id <= 0) {
                    http_response_code(400);
                    echo json_encode(['error' => 'id required']);
                    break;
                }
                $stmt = $pdo->prepare('DELETE FROM anydesk_client_map WHERE id = ?');
                $stmt->execute([$id]);
                echo json_encode(['ok' => true, 'deleted' => $stmt->rowCount()]);
                break;

            case 'anydesk_sessions':
                require_admin_session($pdo, bearer_token());
                anydesk_maybe_sync($pdo, $config);
                $where = [];
                $params = [];
                if (($t = trim((string)($_GET['tenant'] ?? ''))) !== '') {
                    $where[] = 'tenant = ?';
                    $params[] = $t;
                }
                if (($c = trim((string)($_GET['category'] ?? ''))) !== '') {
                    if ($c === 'unclassified') {
                        $where[] = 'category IS NULL';
                    } else {
                        $where[] = 'category = ?';
                        $params[] = $c;
                    }
                }
                if (($from = trim((string)($_GET['from'] ?? ''))) !== '') {
                    $where[] = 'start_time >= ?';
                    $params[] = $from;
                }
                if (($to = trim((string)($_GET['to'] ?? ''))) !== '') {
                    $where[] = 'start_time <= ?';
                    $params[] = $to;
                }
                $sql = 'SELECT * FROM anydesk_sessions';
                if (!empty($where)) $sql .= ' WHERE ' . implode(' AND ', $where);
                $sql .= ' ORDER BY start_time DESC LIMIT 500';
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);
                echo json_encode(['sessions' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
                break;

            case 'anydesk_session_classify':
                $admin = require_admin_session($pdo, bearer_token());
                $data = json_decode((string)file_get_contents('php://input'), true);
                if (!is_array($data)) $data = [];
                $id = (int)($data['id'] ?? 0);
                $category = $data['category'] ?? null;
                $note = array_key_exists('note', $data) ? (string)$data['note'] : null;
                if ($id <= 0) {
                    http_response_code(400);
                    echo json_encode(['error' => 'id required']);
                    break;
                }
                if ($category !== null && !in_array($category, ['billable', 'training', 'internal'], true)) {
                    http_response_code(400);
                    echo json_encode(['error' => 'category must be billable, training, internal, or null']);
                    break;
                }
                $pdo->prepare('UPDATE anydesk_sessions SET category=?, note=?, classified_by=?, classified_at=NOW() WHERE id=?')
                    ->execute([$category, $note, $admin['username'], $id]);
                echo json_encode(['ok' => true]);
                break;

            case 'anydesk_summary':
                require_admin_session($pdo, bearer_token());
                $where = ['end_time IS NOT NULL'];
                $params = [];
                if (($from = trim((string)($_GET['from'] ?? ''))) !== '') {
                    $where[] = 'start_time >= ?';
                    $params[] = $from;
                }
                if (($to = trim((string)($_GET['to'] ?? ''))) !== '') {
                    $where[] = 'start_time <= ?';
                    $params[] = $to;
                }
                $sql = "SELECT
                            COALESCE(tenant, '(unassigned)') AS tenant,
                            DATE_FORMAT(start_time, '%Y-%m') AS month,
                            SUM(CASE WHEN category = 'billable' THEN billed_minutes ELSE 0 END) AS billable_minutes,
                            SUM(CASE WHEN category = 'training' THEN billed_minutes ELSE 0 END) AS training_minutes,
                            SUM(CASE WHEN category = 'internal' THEN billed_minutes ELSE 0 END) AS internal_minutes,
                            SUM(CASE WHEN category IS NULL THEN billed_minutes ELSE 0 END) AS unclassified_minutes,
                            COUNT(*) AS session_count
                        FROM anydesk_sessions
                        WHERE " . implode(' AND ', $where) . '
                        GROUP BY tenant, month
                        ORDER BY month DESC, tenant';
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);
                echo json_encode(['summary' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
                break;
        }
    } else {
    // ── Legacy actions — session token OR the shared viewer_password ───────
    $identity = null;
    $auth_header = get_auth_header();
    if (preg_match('/Bearer\s+(.+)/i', $auth_header, $m)) {
        $identity = resolve_user_session($pdo, trim($m[1]));
    }
    if ($identity === null) {
        login_lockout_check($config, $client_ip);
        if (!preg_match('/Bearer\s+(.+)/i', $auth_header, $m)) {
            login_lockout_record($config, $client_ip, false);
            http_response_code(401);
            echo json_encode(['error' => 'unauthorized']);
            exit;
        }
        $provided = trim($m[1]);
        $password_ok = hash_equals($config['viewer_password'], $provided);
        $totp_ok = true;
        if ($password_ok && !empty($config['viewer_totp_secret'])) {
            $totp_ok = totp_verify($config['viewer_totp_secret'], get_totp_header());
        }
        if (!$password_ok || !$totp_ok) {
            login_lockout_record($config, $client_ip, false);
            http_response_code(401);
            echo json_encode(['error' => $password_ok ? 'invalid or missing TOTP code' : 'invalid password']);
            exit;
        }
        login_lockout_record($config, $client_ip, true);
        // Legacy shared password = full, global admin — unchanged behavior
        // for every deployment that hasn't migrated to per-user accounts yet.
        $identity = ['id' => null, 'username' => null, 'role' => 'admin', 'allowed_tenants' => null];
    }

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
            unset($r);
            $rows = array_values(array_filter($rows, function ($r) use ($identity) { return tenant_allowed($identity, $r['id']); }));
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
            require_tenant($identity, $tenant);
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
            require_tenant($identity, $tenant);
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

        // Agent self-backup (BCP) — metadata-only listing and full
        // download. Admin-only even for a tenant-scoped identity: this is
        // the one thing on this server closest to "everything an attacker
        // would want" (encrypted, but still every credential/key the agent
        // has), so it gets a stricter check than the usual read actions.
        case 'backup_list':
            $tenant = $_GET['tenant'] ?? '';
            if ($tenant === '') {
                http_response_code(400);
                echo json_encode(['error' => 'tenant query param required']);
                break;
            }
            require_tenant($identity, $tenant);
            if ($identity['role'] !== 'admin') {
                http_response_code(403);
                echo json_encode(['error' => 'admin_role_required']);
                break;
            }
            $stmt = $pdo->prepare(
                'SELECT id, created_at, size_bytes FROM agent_backups WHERE tenant = ? ORDER BY created_at DESC LIMIT 20'
            );
            $stmt->execute([$tenant]);
            echo json_encode(['backups' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
            break;

        case 'backup_download':
            $tenant = $_GET['tenant'] ?? '';
            $backup_id = (int)($_GET['id'] ?? 0);
            if ($tenant === '' || $backup_id <= 0) {
                http_response_code(400);
                echo json_encode(['error' => 'tenant and id required']);
                break;
            }
            require_tenant($identity, $tenant);
            if ($identity['role'] !== 'admin') {
                http_response_code(403);
                echo json_encode(['error' => 'admin_role_required']);
                break;
            }
            $stmt = $pdo->prepare(
                'SELECT payload, created_at, size_bytes FROM agent_backups WHERE id = ? AND tenant = ?'
            );
            $stmt->execute([$backup_id, $tenant]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$row) {
                http_response_code(404);
                echo json_encode(['error' => 'not found']);
                break;
            }
            $envelope = json_decode($row['payload'], true);
            if (!is_array($envelope)) {
                http_response_code(500);
                echo json_encode(['error' => 'stored backup is not valid JSON']);
                break;
            }
            echo json_encode([
                'created_at' => $row['created_at'],
                'size_bytes' => (int)$row['size_bytes'],
                'envelope' => $envelope,
            ]);
            break;

        case 'usage':
            require_global($identity);
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
            require_global($identity);
            require_write($identity);
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
            require_tenant($identity, $tenant);
            require_write($identity);
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
            require_tenant($identity, $tenant);
            require_write($identity);
            $state_dir = $config['state_dir'] ?? __DIR__ . '/state';
            if (!is_dir($state_dir)) @mkdir($state_dir, 0700, true);
            $safe = preg_replace('/[^a-zA-Z0-9_-]/', '_', $tenant);
            file_put_contents($state_dir . '/restart_pending_' . $safe, date('c'));
            $pdo->prepare('INSERT INTO activity_log (tenant, event_type, message, details) VALUES (?, "restart_queued", ?, ?)')
                ->execute([$tenant, "Restart zakolejkowany dla {$tenant}", json_encode(['queued_at'=>date('c')])]);
            echo json_encode(['ok'=>true,'tenant'=>$tenant,'queued_at'=>date('c'),'note'=>'Delivered on next heartbeat (max 2 min)']);
            break;

        case 'pending_restarts':
            require_global($identity);
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

        case 'request_supply_chain_scan':
            $tenant = $_GET['tenant'] ?? '';
            if ($tenant === '') { http_response_code(400); echo json_encode(['error'=>'tenant required']); break; }
            require_tenant($identity, $tenant);
            require_write($identity);
            $state_dir = $config['state_dir'] ?? __DIR__ . '/state';
            if (!is_dir($state_dir)) @mkdir($state_dir, 0700, true);
            $safe = preg_replace('/[^a-zA-Z0-9_-]/', '_', $tenant);
            file_put_contents($state_dir . '/supplychain_pending_' . $safe, date('c'));
            $pdo->prepare('INSERT INTO activity_log (tenant, event_type, message, details) VALUES (?, "supply_chain_scan_queued", ?, ?)')
                ->execute([$tenant, "Skan lancucha dostaw zakolejkowany dla {$tenant}", json_encode(['queued_at'=>date('c')])]);
            echo json_encode(['ok'=>true,'tenant'=>$tenant,'queued_at'=>date('c'),'note'=>'Delivered on next heartbeat (max 2 min)']);
            break;

        case 'pending_supply_chain_scans':
            require_global($identity);
            $state_dir = $config['state_dir'] ?? __DIR__ . '/state';
            $pending = [];
            if (is_dir($state_dir)) {
                foreach (glob($state_dir . '/supplychain_pending_*') as $f) {
                    $tenant = substr(basename($f), strlen('supplychain_pending_'));
                    $pending[] = ['tenant' => $tenant, 'queued_at' => date('c', filemtime($f))];
                }
            }
            echo json_encode(['pending' => $pending]);
            break;

        case 'supply_chain_status_all':
            // Aggregate view across every tenant this identity can see, for
            // Central's "run the supply-chain scan on all agents from here"
            // panel — same subquery pattern as the 'tenants' action below
            // (latest snapshot payload per tenant, no E2E key needed since
            // supply_chain_status travels as plaintext envelope metadata,
            // same treatment as firmware_status).
            $stmt = $pdo->query(
                'SELECT t.id AS tenant, t.last_seen,
                        TIMESTAMPDIFF(SECOND, t.last_seen, NOW()) AS age_sec,
                        (SELECT payload FROM snapshots
                         WHERE tenant = t.id
                         ORDER BY received_at DESC LIMIT 1) AS _latest_payload
                 FROM tenants t
                 ORDER BY t.id'
            );
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $result = [];
            foreach ($rows as $r) {
                $sc = null;
                if (!empty($r['_latest_payload'])) {
                    $meta = json_decode($r['_latest_payload'], true);
                    if (is_array($meta)) { $sc = $meta['supply_chain_status'] ?? null; }
                }
                $result[] = [
                    'tenant' => $r['tenant'],
                    'last_seen' => $r['last_seen'],
                    'age_sec' => $r['age_sec'] !== null ? (int)$r['age_sec'] : null,
                    'supply_chain_status' => $sc,
                ];
            }
            $result = array_values(array_filter($result, function ($r) use ($identity) { return tenant_allowed($identity, $r['tenant']); }));
            echo json_encode(['tenants' => $result]);
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
            require_tenant($identity, $tenant);
            require_write($identity);
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
            require_global($identity);
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
            require_tenant($identity, $tenant);
            require_write($identity);
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
            require_global($identity);
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
            require_global($identity);
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

        // Alerts — channels are cross-tenant infrastructure (a channel isn't
        // owned by one tenant, rules from multiple tenants can share one),
        // so channel management stays global-admin-only.
        case 'alert_channels':
            require_global($identity);
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
            require_global($identity);
            require_write($identity);
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
            require_global($identity);
            require_write($identity);
            $id = (int)($_GET['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $stmt = $pdo->prepare('DELETE FROM notification_channels WHERE id=?'); $stmt->execute([$id]);
            echo json_encode(['ok'=>true,'deleted'=>$stmt->rowCount()]);
            break;

        case 'alert_channel_toggle':
            require_global($identity);
            require_write($identity);
            $id = (int)($_GET['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $pdo->prepare('UPDATE notification_channels SET enabled=1-enabled WHERE id=?')->execute([$id]);
            echo json_encode(['ok'=>true]);
            break;

        case 'alert_channel_test':
            require_global($identity);
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
            unset($r);
            // Global rules (tenant NULL) apply to everyone and stay visible
            // to tenant-scoped users too — only rule ADD/DELETE/TOGGLE of a
            // global rule needs a global identity.
            $rows = array_values(array_filter($rows, function ($r) use ($identity) { return $r['tenant'] === null || tenant_allowed($identity, $r['tenant']); }));
            echo json_encode(['rules'=>$rows]);
            break;

        case 'alert_rule_add':
            require_write($identity);
            $data = json_decode(file_get_contents('php://input'), true);
            if (!is_array($data)) { http_response_code(400); echo json_encode(['error'=>'invalid body']); break; }
            $ev = (string)($data['event_type']??''); $chs = $data['channel_ids'] ?? [];
            if ($ev==='' || !is_array($chs) || empty($chs)) { http_response_code(400); echo json_encode(['error'=>'event_type and channel_ids required']); break; }
            $rule_tenant = trim((string)($data['tenant']??''))?:null;
            if ($rule_tenant === null) {
                require_global($identity); // only a global admin may add a rule that applies to every tenant
            } else {
                require_tenant($identity, $rule_tenant);
            }
            $stmt = $pdo->prepare('INSERT INTO alert_rules (name,tenant,event_type,min_count,cooldown_sec,channel_ids,enabled) VALUES (?,?,?,?,?,?,1)');
            $stmt->execute([
                trim((string)($data['name']??''))?:null,
                $rule_tenant,
                $ev, max(1,(int)($data['min_count']??1)), max(0,(int)($data['cooldown_sec']??3600)),
                json_encode(array_values(array_map('intval',$chs))),
            ]);
            echo json_encode(['ok'=>true,'id'=>(int)$pdo->lastInsertId()]);
            break;

        case 'alert_rule_delete':
            require_write($identity);
            $id = (int)($_GET['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $rt = $pdo->prepare('SELECT tenant FROM alert_rules WHERE id=?'); $rt->execute([$id]);
            $rule_tenant = $rt->fetchColumn();
            if ($rule_tenant === false) { http_response_code(404); echo json_encode(['error'=>'not found']); break; }
            if ($rule_tenant === null) { require_global($identity); } else { require_tenant($identity, $rule_tenant); }
            $stmt = $pdo->prepare('DELETE FROM alert_rules WHERE id=?'); $stmt->execute([$id]);
            echo json_encode(['ok'=>true,'deleted'=>$stmt->rowCount()]);
            break;

        case 'alert_rule_toggle':
            require_write($identity);
            $id = (int)($_GET['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $rt = $pdo->prepare('SELECT tenant FROM alert_rules WHERE id=?'); $rt->execute([$id]);
            $rule_tenant = $rt->fetchColumn();
            if ($rule_tenant === false) { http_response_code(404); echo json_encode(['error'=>'not found']); break; }
            if ($rule_tenant === null) { require_global($identity); } else { require_tenant($identity, $rule_tenant); }
            $pdo->prepare('UPDATE alert_rules SET enabled=1-enabled WHERE id=?')->execute([$id]);
            echo json_encode(['ok'=>true]);
            break;

        case 'alert_history':
            $limit = min(200, max(1, (int)($_GET['limit']??50)));
            $tenant = $_GET['tenant'] ?? '';
            if ($tenant !== '') {
                require_tenant($identity, $tenant);
                $stmt = $pdo->prepare('SELECT id,triggered_at,tenant,event_type,event_data,matched_rule_id,notifications_result FROM alert_history WHERE tenant=? ORDER BY triggered_at DESC LIMIT '.$limit);
                $stmt->execute([$tenant]);
            } elseif ($identity['allowed_tenants'] === null) {
                $stmt = $pdo->query('SELECT id,triggered_at,tenant,event_type,event_data,matched_rule_id,notifications_result FROM alert_history ORDER BY triggered_at DESC LIMIT '.$limit);
            } elseif (empty($identity['allowed_tenants'])) {
                echo json_encode(['history'=>[]]);
                break;
            } else {
                $ph = implode(',', array_fill(0, count($identity['allowed_tenants']), '?'));
                $stmt = $pdo->prepare("SELECT id,triggered_at,tenant,event_type,event_data,matched_rule_id,notifications_result FROM alert_history WHERE tenant IN ($ph) ORDER BY triggered_at DESC LIMIT ".$limit);
                $stmt->execute($identity['allowed_tenants']);
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
            $rows = $pdo->query('SELECT id,tenant,name,ip,check_port,interval_sec,channel_ids,enabled,source,source_device_id,source_device_name,source_iface,last_seen_from_agent,last_check,last_status,last_state_change,consecutive_fails,last_check_detail,created_at FROM edge_devices ORDER BY tenant,name')->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$r) {
                $r['channel_ids'] = json_decode($r['channel_ids']??'[]',true)?:[];
                $r['enabled']=(int)$r['enabled']; $r['interval_sec']=(int)$r['interval_sec'];
                $r['check_port'] = $r['check_port']!==null ? (int)$r['check_port'] : null;
                $r['consecutive_fails']=(int)$r['consecutive_fails'];
            }
            unset($r);
            $rows = array_values(array_filter($rows, function ($r) use ($identity) { return tenant_allowed($identity, $r['tenant']); }));
            echo json_encode(['devices'=>$rows]);
            break;

        case 'edge_device_update':
            require_write($identity);
            $data = json_decode(file_get_contents('php://input'), true);
            if (!is_array($data)) { http_response_code(400); echo json_encode(['error'=>'invalid body']); break; }
            $id = (int)($data['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $owt = $pdo->prepare('SELECT tenant FROM edge_devices WHERE id=?'); $owt->execute([$id]);
            $owner_tenant = $owt->fetchColumn();
            if ($owner_tenant === false) { http_response_code(404); echo json_encode(['error'=>'not found']); break; }
            require_tenant($identity, $owner_tenant);
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
            require_write($identity);
            $data = json_decode(file_get_contents('php://input'), true);
            if (!is_array($data)) { http_response_code(400); echo json_encode(['error'=>'invalid body']); break; }
            $tenant_f = trim((string)($data['tenant']??'')); $name = trim((string)($data['name']??'')); $ip = trim((string)($data['ip']??''));
            if ($tenant_f===''||$name===''||$ip==='') { http_response_code(400); echo json_encode(['error'=>'tenant, name, ip required']); break; }
            require_tenant($identity, $tenant_f);
            $port = isset($data['check_port'])&&$data['check_port']!=='' ? (int)$data['check_port'] : null;
            $chs = is_array($data['channel_ids']??null)?$data['channel_ids']:[];
            $stmt = $pdo->prepare('INSERT INTO edge_devices (tenant,name,ip,check_port,interval_sec,channel_ids,enabled,source) VALUES (?,?,?,?,?,?,1,"manual") ON DUPLICATE KEY UPDATE name=VALUES(name),check_port=VALUES(check_port),interval_sec=VALUES(interval_sec),channel_ids=VALUES(channel_ids),enabled=1');
            $stmt->execute([$tenant_f,$name,$ip,$port,max(60,(int)($data['interval_sec']??900)),json_encode(array_values(array_map('intval',$chs)))]);
            echo json_encode(['ok'=>true,'id'=>(int)$pdo->lastInsertId()]);
            break;

        case 'edge_device_delete':
            require_write($identity);
            $id = (int)($_GET['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $owt = $pdo->prepare('SELECT tenant FROM edge_devices WHERE id=?'); $owt->execute([$id]);
            $owner_tenant = $owt->fetchColumn();
            if ($owner_tenant === false) { http_response_code(404); echo json_encode(['error'=>'not found']); break; }
            require_tenant($identity, $owner_tenant);
            $pdo->prepare('DELETE FROM edge_events WHERE edge_id=?')->execute([$id]);
            $stmt = $pdo->prepare('DELETE FROM edge_devices WHERE id=?'); $stmt->execute([$id]);
            echo json_encode(['ok'=>true,'deleted'=>$stmt->rowCount()]);
            break;

        case 'edge_device_toggle':
            require_write($identity);
            $id = (int)($_GET['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $owt = $pdo->prepare('SELECT tenant FROM edge_devices WHERE id=?'); $owt->execute([$id]);
            $owner_tenant = $owt->fetchColumn();
            if ($owner_tenant === false) { http_response_code(404); echo json_encode(['error'=>'not found']); break; }
            require_tenant($identity, $owner_tenant);
            $pdo->prepare('UPDATE edge_devices SET enabled=1-enabled WHERE id=?')->execute([$id]);
            echo json_encode(['ok'=>true]);
            break;

        case 'edge_device_check_now':
            require_write($identity);
            $id = (int)($_GET['id']??0); if ($id<=0) { http_response_code(400); echo json_encode(['error'=>'id required']); break; }
            $stmt = $pdo->prepare('SELECT * FROM edge_devices WHERE id=?'); $stmt->execute([$id]);
            $d = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$d) { http_response_code(404); echo json_encode(['error'=>'not found']); break; }
            require_tenant($identity, $d['tenant']);
            $res = edge_check_one($pdo,$d);
            echo json_encode(['ok'=>true,'result'=>$res]);
            break;

        case 'edge_events':
            $limit = min(200, max(1, (int)($_GET['limit']??100)));
            $edge_id = (int)($_GET['edge_id']??0);
            if ($edge_id>0) {
                $owt = $pdo->prepare('SELECT tenant FROM edge_devices WHERE id=?'); $owt->execute([$edge_id]);
                $owner_tenant = $owt->fetchColumn();
                if ($owner_tenant !== false) { require_tenant($identity, $owner_tenant); }
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
            unset($r);
            $rows = array_values(array_filter($rows, function ($r) use ($identity) { return tenant_allowed($identity, $r['tenant']); }));
            echo json_encode(['events'=>$rows]);
            break;

        case 'activity_log':
            $limit = min(200, max(1, (int)($_GET['limit']??50)));
            $tenant = $_GET['tenant'] ?? '';
            if ($tenant !== '') {
                require_tenant($identity, $tenant);
                $stmt = $pdo->prepare('SELECT id,ts,tenant,event_type,message,details FROM activity_log WHERE tenant=? ORDER BY ts DESC LIMIT '.$limit);
                $stmt->execute([$tenant]);
            } elseif ($identity['allowed_tenants'] === null) {
                $stmt = $pdo->query('SELECT id,ts,tenant,event_type,message,details FROM activity_log ORDER BY ts DESC LIMIT '.$limit);
            } elseif (empty($identity['allowed_tenants'])) {
                echo json_encode(['activity' => []]);
                break;
            } else {
                $ph = implode(',', array_fill(0, count($identity['allowed_tenants']), '?'));
                $stmt = $pdo->prepare("SELECT id,ts,tenant,event_type,message,details FROM activity_log WHERE tenant IN ($ph) ORDER BY ts DESC LIMIT ".$limit);
                $stmt->execute($identity['allowed_tenants']);
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
    }
} catch (Throwable $e) {
    error_log('[mm-api] ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'server error']);
}
