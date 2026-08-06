<?php
/**
 * RFC 6238 TOTP verification — zero dependencies (pure PHP, no composer).
 *
 * Parameters match pyotp's defaults, already used for the local agent's MFA
 * (backend/services/auth.py): SHA1, 6 digits, 30s step, ±1 step tolerance.
 * This is a SEPARATE secret from any per-agent MFA secret — it protects only
 * this central server's shared viewer login (desktop "Centralny" view +
 * the phone viewer in ovh/viewer/), so both of those need the same secret
 * configured (see config.php's viewer_totp_secret comment for how to
 * generate one).
 */

declare(strict_types=1);

function _totp_base32_decode(string $b32): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $b32 = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $b32) ?? '');
    $bits = '';
    foreach (str_split($b32) as $char) {
        $pos = strpos($alphabet, $char);
        if ($pos === false) continue;
        $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
    }
    $bytes = '';
    foreach (str_split($bits, 8) as $byte) {
        if (strlen($byte) === 8) $bytes .= chr((int)bindec($byte));
    }
    return $bytes;
}

function _totp_code_at_step(string $secret, int $step): string {
    $key = _totp_base32_decode($secret);
    // 8-byte big-endian counter, per RFC 4226.
    $counter = pack('N*', 0) . pack('N*', $step);
    $hash = hash_hmac('sha1', $counter, $key, true);
    $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
    $code = (
        ((ord($hash[$offset]) & 0x7F) << 24) |
        ((ord($hash[$offset + 1]) & 0xFF) << 16) |
        ((ord($hash[$offset + 2]) & 0xFF) << 8) |
        (ord($hash[$offset + 3]) & 0xFF)
    ) % 1000000;
    return str_pad((string)$code, 6, '0', STR_PAD_LEFT);
}

/** Verify a submitted 6-digit code against `$secret`, tolerating clock drift
 * of up to `$window` 30s steps either side (default ±1, i.e. a 90s-wide
 * acceptance window) — same tolerance as the local agent's pyotp check. */
function totp_verify(string $secret, string $code, int $window = 1): bool {
    $code = trim($code);
    if ($code === '' || !preg_match('/^\d{6}$/', $code) || $secret === '') {
        return false;
    }
    $now_step = (int) floor(time() / 30);
    for ($i = -$window; $i <= $window; $i++) {
        if (hash_equals(_totp_code_at_step($secret, $now_step + $i), $code)) {
            return true;
        }
    }
    return false;
}
