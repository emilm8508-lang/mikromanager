<?php
/**
 * Zero-dependency PHP SAST for ovh/*.php — the Bandit/eslint-plugin-security
 * equivalent for the central server's code. No Composer/PHAR download: this
 * codebase deliberately has zero third-party PHP dependencies (see totp.php,
 * anydesk.php), and OVH's shared hosting has exec() disabled anyway, so this
 * script is meant to run OFF the OVH server — on whichever local agent
 * machine happens to have a PHP CLI available (backend/services/
 * supply_chain.py invokes it via subprocess, skips gracefully if php isn't
 * on PATH). It scans this same git checkout's ovh/ directory, since every
 * agent already has one via git fetch/reset.
 *
 * Flags calls to functions that are almost always a red flag in ordinary
 * application code — the same "dangerous function" rule family every real
 * PHP SAST tool leads with (Bandit's B602-family subprocess rules are the
 * closest Python analogue). Uses token_get_all() (built into PHP, zero
 * deps) rather than regex, so it isn't fooled by the function name showing
 * up in a comment or a string literal.
 *
 * Usage: php php_security_lint.php <ovh_dir>
 * Output: single line of JSON on stdout: {"ok":true,"findings":[...],"counts":{...}}
 */

$DANGEROUS_FUNCTIONS = [
    'eval'            => 'high',
    'system'          => 'high',
    'exec'            => 'high',
    'shell_exec'      => 'high',
    'passthru'        => 'high',
    'proc_open'       => 'high',
    'popen'           => 'high',
    'assert'          => 'medium',
    'create_function' => 'medium',
    'unserialize'     => 'medium',
    'extract'         => 'medium',
];

function lint_file(string $path, array $dangerous): array {
    $findings = [];
    $src = @file_get_contents($path);
    if ($src === false) {
        return $findings;
    }
    $tokens = token_get_all($src);
    $count = count($tokens);
    for ($i = 0; $i < $count; $i++) {
        $tok = $tokens[$i];
        if (!is_array($tok) || $tok[0] !== T_STRING) {
            continue;
        }
        $name = strtolower($tok[1]);
        if (!isset($dangerous[$name])) {
            continue;
        }
        // Only count it as a call if the next non-whitespace token is '('.
        $j = $i + 1;
        while ($j < $count && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
            $j++;
        }
        if (!isset($tokens[$j]) || $tokens[$j] !== '(') {
            continue;
        }
        $findings[] = [
            'file' => $path,
            'line' => $tok[2],
            'function' => $name,
            'severity' => $dangerous[$name],
        ];
    }
    return $findings;
}

function collect_php_files(string $dir): array {
    $out = [];
    $items = @scandir($dir);
    if ($items === false) return $out;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $full = $dir . DIRECTORY_SEPARATOR . $item;
        if (is_dir($full)) {
            // Skip this tool's own directory and any vendored/viewer static assets.
            if ($item === 'tools' || $item === 'viewer') continue;
            $out = array_merge($out, collect_php_files($full));
        } elseif (substr($item, -4) === '.php') {
            $out[] = $full;
        }
    }
    return $out;
}

$dir = $argv[1] ?? null;
if (!$dir || !is_dir($dir)) {
    echo json_encode(['ok' => false, 'error' => 'ovh directory not found: ' . ($dir ?? '(none given)')]);
    exit(1);
}

$files = collect_php_files($dir);
$findings = [];
$counts = ['high' => 0, 'medium' => 0];
foreach ($files as $f) {
    foreach (lint_file($f, $DANGEROUS_FUNCTIONS) as $finding) {
        $finding['file'] = str_replace($dir . DIRECTORY_SEPARATOR, '', $finding['file']);
        $findings[] = $finding;
        $counts[$finding['severity']] = ($counts[$finding['severity']] ?? 0) + 1;
    }
}

echo json_encode([
    'ok' => true,
    'files_scanned' => count($files),
    'findings' => $findings,
    'counts' => $counts,
]);
