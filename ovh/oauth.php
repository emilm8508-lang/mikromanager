<?php
/**
 * MikroManager Central — the OAuth 2.1 authorization server of the MCP connector (see mcp_lib.php for the whole picture).
 *
 * Paths (PATH_INFO, with ?a= as a fallback for the endpoints):
 *   /.well-known/oauth-authorization-server, /.well-known/openid-configuration  → metadata (the MCP clients try
 *        {issuer}/.well-known/openid-configuration among others, which is how this works from a sub-folder without the domain root)
 *   /register   → Dynamic Client Registration (RFC 7591), only redirect URIs of allowed hosts
 *   /authorize  → the sign-in and consent page: Central username, password, TOTP when the account has it on
 *   /token      → authorization_code (PKCE S256) and refresh_token (rotated; a reused one revokes the whole chain)
 *   /revoke     → RFC 7009
 */

declare(strict_types=1);
$config = require __DIR__ . '/config.php';
require_once __DIR__ . '/totp.php';
require_once __DIR__ . '/mcp_lib.php';

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

if (($config['mcp_enabled'] ?? true) === false) {
    mcp_json(['error' => 'temporarily_unavailable', 'error_description' => 'the MCP connector is turned off in config.php'], 503);
    exit;
}

$path = (string)($_SERVER['PATH_INFO'] ?? '');
$a = (string)($_GET['a'] ?? '');
$route = $a !== '' ? $a : trim($path, '/');
$method = (string)($_SERVER['REQUEST_METHOD'] ?? 'GET');

if ($method === 'OPTIONS') {                                           // browser-based clients (MCP Inspector) - the metadata and token are public endpoints
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Headers: Authorization, Content-Type, MCP-Protocol-Version');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    http_response_code(204);
    exit;
}

try {
    switch ($route) {
        case '.well-known/oauth-authorization-server':
        case '.well-known/openid-configuration':
        case 'metadata':
            header('Access-Control-Allow-Origin: *');
            oauth_metadata($config);
            break;
        case 'register':
            header('Access-Control-Allow-Origin: *');
            oauth_register(mcp_pdo($config), $config);
            break;
        case 'authorize':
            oauth_authorize(mcp_pdo($config), $config);
            break;
        case 'token':
            header('Access-Control-Allow-Origin: *');
            oauth_token(mcp_pdo($config), $config);
            break;
        case 'revoke':
            header('Access-Control-Allow-Origin: *');
            oauth_revoke(mcp_pdo($config));
            break;
        default:
            mcp_json(['error' => 'not_found'], 404);
    }
} catch (Throwable $e) {
    error_log('[oauth.php] ' . $e->getMessage());
    mcp_json(['error' => 'server_error'], 500);
}

function oauth_metadata(array $config): void {
    $iss = mcp_issuer($config);
    mcp_json([
        'issuer' => $iss,
        'authorization_endpoint' => $iss . '/authorize',
        'token_endpoint' => $iss . '/token',
        'registration_endpoint' => $iss . '/register',
        'revocation_endpoint' => $iss . '/revoke',
        'response_types_supported' => ['code'],
        'response_modes_supported' => ['query'],
        'grant_types_supported' => ['authorization_code', 'refresh_token'],
        'code_challenge_methods_supported' => ['S256'],
        'token_endpoint_auth_methods_supported' => ['none', 'client_secret_post', 'client_secret_basic'],
        'revocation_endpoint_auth_methods_supported' => ['none', 'client_secret_post', 'client_secret_basic'],
        'scopes_supported' => [MCP_SCOPE],
        'client_id_metadata_document_supported' => true,
        'authorization_response_iss_parameter_supported' => true,
        'subject_types_supported' => ['public'],
        'service_documentation' => mcp_base_url($config) . '/mcp.php',
    ]);
}

// ── Dynamic Client Registration ──────────────────────────────────────────────

function oauth_register(PDO $pdo, array $config): void {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { mcp_json(['error' => 'invalid_request'], 405); return; }
    $raw = (string)file_get_contents('php://input', false, null, 0, 32768);
    $d = json_decode($raw, true);
    if (!is_array($d)) { mcp_json(['error' => 'invalid_client_metadata', 'error_description' => 'JSON body required'], 400); return; }
    $uris = $d['redirect_uris'] ?? null;
    if (!is_array($uris) || !$uris || count($uris) > 10) {
        mcp_json(['error' => 'invalid_redirect_uri', 'error_description' => 'redirect_uris: 1-10 URIs'], 400); return;
    }
    foreach ($uris as $u) {
        if (!is_string($u) || strlen($u) > 500 || !mcp_redirect_ok($config, $u)) {
            mcp_json(['error' => 'invalid_redirect_uri', 'error_description' => 'redirect URI not allowed by this server: ' . (is_string($u) ? substr($u, 0, 200) : '?')], 400); return;
        }
    }
    $n = (int)$pdo->query("SELECT COUNT(*) FROM mcp_clients WHERE kind = 'dcr'")->fetchColumn();
    if ($n >= 500) { mcp_json(['error' => 'temporarily_unavailable', 'error_description' => 'too many registered clients'], 503); return; }
    $method = (string)($d['token_endpoint_auth_method'] ?? 'none');
    if (!in_array($method, ['none', 'client_secret_post', 'client_secret_basic'], true)) $method = 'none';
    $client_id = 'mmc_' . bin2hex(random_bytes(16));
    $secret = $method === 'none' ? null : bin2hex(random_bytes(32));
    $name = mb_substr(trim((string)($d['client_name'] ?? '')), 0, 200);
    $pdo->prepare('INSERT INTO mcp_clients (client_id, secret_hash, name, redirect_uris, kind, created, last_used) VALUES (?, ?, ?, ?, ?, ?, ?)')
        ->execute([$client_id, $secret ? hash('sha256', $secret) : null, $name, json_encode(array_values($uris)), 'dcr', time(), time()]);
    $out = [
        'client_id' => $client_id, 'client_id_issued_at' => time(), 'client_name' => $name, 'redirect_uris' => array_values($uris),
        'grant_types' => ['authorization_code', 'refresh_token'], 'response_types' => ['code'], 'token_endpoint_auth_method' => $method,
        'scope' => MCP_SCOPE,
    ];
    if ($secret) { $out['client_secret'] = $secret; $out['client_secret_expires_at'] = 0; }
    mcp_json($out, 201);
}

// ── Authorization (sign-in + consent) ────────────────────────────────────────

/** The authorization request, validated. ['error' => html message] when the client cannot even be sent back. */
function oauth_request(PDO $pdo, array $config, array $q): array {
    $client_id = (string)($q['client_id'] ?? '');
    $redirect = (string)($q['redirect_uri'] ?? '');
    $client = mcp_client($pdo, $config, $client_id);
    if (!$client) return ['fatal' => 'Nieznana aplikacja (client_id) albo jej opis nie jest dostępny.'];
    if ($redirect === '' && count($client['redirect_uris']) === 1) $redirect = (string)$client['redirect_uris'][0];
    if (!in_array($redirect, $client['redirect_uris'], true)) return ['fatal' => 'Adres powrotu (redirect_uri) nie jest zarejestrowany dla tej aplikacji.'];
    if (!mcp_redirect_ok($config, $redirect)) return ['fatal' => 'Ta Centrala nie pozwala wracać pod adres ' . (parse_url($redirect, PHP_URL_HOST) ?: '?') . '.'];
    $r = ['client' => $client, 'redirect_uri' => $redirect, 'state' => (string)($q['state'] ?? ''), 'client_id' => $client_id];
    if (($q['response_type'] ?? '') !== 'code') return $r + ['error' => 'unsupported_response_type'];
    $challenge = (string)($q['code_challenge'] ?? '');
    if (($q['code_challenge_method'] ?? '') !== 'S256' || !preg_match('/^[A-Za-z0-9_-]{43,128}$/', $challenge)) {
        return $r + ['error' => 'invalid_request', 'error_description' => 'PKCE with S256 is required'];
    }
    $resource = (string)($q['resource'] ?? '');
    if ($resource !== '' && !mcp_same_resource($resource, mcp_resource_url($config))) return $r + ['error' => 'invalid_target'];
    $scope = trim((string)($q['scope'] ?? ''));
    foreach (preg_split('/\s+/', $scope, -1, PREG_SPLIT_NO_EMPTY) as $s) {
        if ($s !== MCP_SCOPE && !in_array($s, ['openid', 'offline_access', 'profile'], true)) return $r + ['error' => 'invalid_scope'];
    }
    return $r + ['challenge' => $challenge, 'resource' => mcp_resource_url($config), 'scope' => MCP_SCOPE];
}

function oauth_redirect(string $uri, array $params): void {
    $sep = strpos($uri, '?') === false ? '?' : '&';
    header('Location: ' . $uri . $sep . http_build_query($params));
    http_response_code(302);
}

function oauth_authorize(PDO $pdo, array $config): void {
    // No form-action: Chrome applies it to the redirect after the form too, which goes to the client (claude.ai, chatgpt.com, localhost).
    header('Content-Security-Policy: default-src \'none\'; style-src \'unsafe-inline\'; frame-ancestors \'none\'');
    header('X-Frame-Options: DENY');
    header('Cache-Control: no-store');
    $post = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';
    $q = $post ? $_POST : $_GET;
    $req = oauth_request($pdo, $config, $q);
    if (isset($req['fatal'])) { oauth_page($config, null, $req['fatal'], [], null); return; }
    $back = ['iss' => mcp_issuer($config)] + ($req['state'] !== '' ? ['state' => $req['state']] : []);
    if (isset($req['error'])) {
        oauth_redirect($req['redirect_uri'], ['error' => $req['error']] + (isset($req['error_description']) ? ['error_description' => $req['error_description']] : []) + $back);
        return;
    }
    $keep = [];
    foreach (['response_type', 'client_id', 'redirect_uri', 'code_challenge', 'code_challenge_method', 'state', 'scope', 'resource'] as $k) {
        if (isset($q[$k]) && is_string($q[$k])) $keep[$k] = $q[$k];
    }
    if (!$post) { oauth_page($config, $req, null, $keep, null); return; }

    if (($q['decision'] ?? '') !== 'allow') { oauth_redirect($req['redirect_uri'], ['error' => 'access_denied'] + $back); return; }
    $username = trim((string)($q['username'] ?? ''));
    $password = (string)($q['password'] ?? '');
    if ($username === '' || $password === '') { oauth_page($config, $req, 'Podaj nazwę użytkownika i hasło.', $keep, $username); return; }
    if (($wait = mcp_locked_for($config, $username)) > 0) {
        oauth_page($config, $req, "Za dużo nieudanych prób - spróbuj za {$wait} s.", $keep, $username); return;
    }
    $st = $pdo->prepare('SELECT * FROM users WHERE username = ? AND is_active = 1');
    $st->execute([$username]);
    $u = $st->fetch(PDO::FETCH_ASSOC);
    $ok = $u && password_verify($password, (string)$u['password_hash']);
    if ($ok && (int)$u['totp_enabled'] === 1) $ok = totp_verify((string)$u['totp_secret'], trim((string)($q['totp'] ?? '')));
    if (!$ok) {
        mcp_lockout_record($config, $username, false);
        oauth_page($config, $req, 'Nieprawidłowa nazwa użytkownika, hasło albo kod 2FA.', $keep, $username); return;
    }
    mcp_lockout_record($config, $username, true);
    $code = bin2hex(random_bytes(32));
    $pdo->prepare('INSERT INTO mcp_codes (code_hash, client_id, user_id, redirect_uri, challenge, resource, scope, exp, family) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
        ->execute([hash('sha256', $code), $req['client_id'], (int)$u['id'], $req['redirect_uri'], $req['challenge'], $req['resource'], $req['scope'], time() + MCP_CODE_TTL, bin2hex(random_bytes(16))]);
    oauth_redirect($req['redirect_uri'], ['code' => $code] + $back);
}

function oauth_page(array $config, ?array $req, ?string $error, array $keep, ?string $username): void {
    header('Content-Type: text/html; charset=utf-8');
    $h = function ($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); };
    $central = parse_url(mcp_base_url($config), PHP_URL_HOST) ?: '';
    echo '<!doctype html><html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>MikroManager Central - połącz konektor</title><style>
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#f1f5f9;color:#0f172a;margin:0;padding:24px 16px}
.box{max-width:440px;margin:0 auto;background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:24px}
h1{font-size:18px;margin:0 0 4px}.muted{color:#64748b;font-size:13px}.app{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:12px;margin:16px 0;font-size:14px}
.host{font-family:ui-monospace,monospace;font-weight:600}.warn{background:#fef3c7;border:1px solid #fcd34d;color:#78350f;border-radius:8px;padding:8px 10px;font-size:13px;margin-top:8px}
.err{background:#fee2e2;border:1px solid #fca5a5;color:#7f1d1d;border-radius:8px;padding:8px 10px;font-size:13px;margin:12px 0}
label{display:block;font-size:13px;margin:12px 0 4px;color:#334155}input{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid #cbd5e1;border-radius:8px;font-size:14px}
ul{font-size:13px;color:#334155;padding-left:18px;margin:8px 0}.row{display:flex;gap:8px;margin-top:18px}
button{flex:1;padding:10px;border-radius:8px;border:1px solid #cbd5e1;background:#fff;font-size:14px;cursor:pointer}button.go{background:#4f46e5;border-color:#4f46e5;color:#fff}
</style></head><body><div class="box">';
    echo '<h1>Połącz z MikroManager Central</h1><div class="muted">' . $h($central) . '</div>';
    if ($req === null) {
        echo '<div class="err">' . $h($error) . '</div></div></body></html>';
        return;
    }
    $rhost = (string)(parse_url($req['redirect_uri'], PHP_URL_HOST) ?: '');
    $name = trim((string)($req['client']['name'] ?? '')) ?: 'Aplikacja bez nazwy';
    echo '<div class="app"><div><b>' . $h($name) . '</b> prosi o dostęp do Centrali.</div>';
    echo '<div style="margin-top:6px">Po zgodzie wrócisz na: <span class="host">' . $h($rhost) . '</span></div>';
    if (mcp_is_local_host($rhost)) {
        echo '<div class="warn">Powrót na <b>localhost</b> - zgódź się tylko wtedy, gdy sam(a) uruchamiasz teraz takiego klienta (np. Claude Desktop, Claude Code, MCP Inspector) na tym komputerze.</div>';
    }
    echo '</div><div style="font-size:13px">Aplikacja będzie mogła <b>tylko czytać</b>:</div><ul>
<li>alerty SOC, ryzyko, anomalie, dostępność, podatności, inwentarz i stan serwerów</li>
<li>wyłącznie klientów, których Twoje konto widzi w Centrali</li></ul>
<div class="muted">Bez zmian w sieciach klientów i bez haseł - dane trafiają do modelu na Twoim koncie AI. Dostęp odbierzesz w Centrali: Asystent AI → Konektor (MCP).</div>';
    if ($error) echo '<div class="err">' . $h($error) . '</div>';
    $action = mcp_issuer($config) . '/authorize';
    echo '<form method="post" action="' . $h($action) . '" autocomplete="on">';
    foreach ($keep as $k => $v) echo '<input type="hidden" name="' . $h($k) . '" value="' . $h($v) . '">';
    echo '<label for="u">Użytkownik Centrali</label><input id="u" name="username" value="' . $h($username ?? '') . '" autocomplete="username" required>';
    echo '<label for="p">Hasło</label><input id="p" type="password" name="password" autocomplete="current-password" required>';
    echo '<label for="t">Kod 2FA (jeśli włączony)</label><input id="t" name="totp" inputmode="numeric" pattern="[0-9 ]*" maxlength="8" autocomplete="one-time-code">';
    echo '<div class="row"><button type="submit" name="decision" value="deny" formnovalidate>Odmów</button><button class="go" type="submit" name="decision" value="allow">Zezwól</button></div>';
    echo '</form></div></body></html>';
}

// ── Token endpoint ───────────────────────────────────────────────────────────

/** The client making a token request; checks its secret when it has one. null = invalid_client (already answered). */
function oauth_token_client(PDO $pdo, array $config): ?array {
    $id = (string)($_POST['client_id'] ?? '');
    $secret = (string)($_POST['client_secret'] ?? '');
    $auth = mcp_auth_header();
    if (stripos($auth, 'Basic ') === 0) {
        $pair = base64_decode(substr($auth, 6), true);
        if ($pair !== false && strpos($pair, ':') !== false) {
            [$bid, $bsec] = explode(':', $pair, 2);
            $id = urldecode($bid); $secret = urldecode($bsec);
        }
    }
    $client = mcp_client($pdo, $config, $id);
    if (!$client || (!empty($client['secret_hash']) && !hash_equals((string)$client['secret_hash'], hash('sha256', $secret)))) {
        mcp_json(['error' => 'invalid_client'], 401, ['WWW-Authenticate: Basic realm="mcp"']);
        return null;
    }
    return $client;
}

function oauth_token(PDO $pdo, array $config): void {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { mcp_json(['error' => 'invalid_request'], 405); return; }
    $client = oauth_token_client($pdo, $config);
    if (!$client) return;
    $grant = (string)($_POST['grant_type'] ?? '');
    $resource = (string)($_POST['resource'] ?? '');
    if ($resource !== '' && !mcp_same_resource($resource, mcp_resource_url($config))) { mcp_json(['error' => 'invalid_target'], 400); return; }

    if ($grant === 'authorization_code') {
        $st = $pdo->prepare('SELECT * FROM mcp_codes WHERE code_hash = ?');
        $st->execute([hash('sha256', (string)($_POST['code'] ?? ''))]);
        $c = $st->fetch(PDO::FETCH_ASSOC);
        if (!$c || $c['client_id'] !== $client['client_id']) { mcp_json(['error' => 'invalid_grant'], 400); return; }
        if ((int)$c['used']) {                                         // a code used twice: whatever it gave is revoked
            mcp_revoke_family($pdo, (string)$c['family']);
            mcp_json(['error' => 'invalid_grant', 'error_description' => 'code already used'], 400); return;
        }
        $pdo->prepare('UPDATE mcp_codes SET used = 1 WHERE code_hash = ?')->execute([$c['code_hash']]);
        $verifier = (string)($_POST['code_verifier'] ?? '');
        if ((int)$c['exp'] < time() || (isset($_POST['redirect_uri']) && $_POST['redirect_uri'] !== $c['redirect_uri'])
            || !preg_match('/^[A-Za-z0-9._~-]{43,128}$/', $verifier) || !hash_equals((string)$c['challenge'], mcp_b64url(hash('sha256', $verifier, true)))) {
            mcp_json(['error' => 'invalid_grant'], 400); return;
        }
        mcp_json(mcp_issue_tokens($pdo, $client['client_id'], (int)$c['user_id'], (string)$c['resource'], (string)$c['scope'], (string)$c['family']));
        return;
    }

    if ($grant === 'refresh_token') {
        $st = $pdo->prepare("SELECT t.*, u.is_active FROM mcp_tokens t LEFT JOIN users u ON u.id = t.user_id WHERE t.token_hash = ? AND t.kind = 'refresh'");
        $st->execute([hash('sha256', (string)($_POST['refresh_token'] ?? ''))]);
        $t = $st->fetch(PDO::FETCH_ASSOC);
        if (!$t || $t['client_id'] !== $client['client_id']) { mcp_json(['error' => 'invalid_grant'], 400); return; }
        if ((int)$t['revoked']) {                                       // a rotated-out refresh token came back: someone holds a copy
            mcp_revoke_family($pdo, (string)$t['family']);
            mcp_json(['error' => 'invalid_grant', 'error_description' => 'refresh token reused'], 400); return;
        }
        if ((int)$t['exp'] < time() || !(int)$t['is_active']) { mcp_json(['error' => 'invalid_grant'], 400); return; }
        $pdo->prepare("UPDATE mcp_tokens SET revoked = 1 WHERE family = ? AND (token_hash = ? OR kind = 'access')")->execute([$t['family'], $t['token_hash']]);
        mcp_json(mcp_issue_tokens($pdo, $client['client_id'], (int)$t['user_id'], (string)$t['resource'], (string)$t['scope'], (string)$t['family']));
        return;
    }
    mcp_json(['error' => 'unsupported_grant_type'], 400);
}

function oauth_revoke(PDO $pdo): void {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { mcp_json(['error' => 'invalid_request'], 405); return; }
    $st = $pdo->prepare('SELECT family FROM mcp_tokens WHERE token_hash = ?');
    $st->execute([hash('sha256', (string)($_POST['token'] ?? ''))]);
    $family = $st->fetchColumn();
    if ($family) mcp_revoke_family($pdo, (string)$family);
    http_response_code(200);                                            // RFC 7009: 200 whether or not the token was known
}
