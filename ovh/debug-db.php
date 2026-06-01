<?php
/**
 * TEMPORARY diagnostic file — DELETE AFTER USE.
 * Tests DB connection and table presence. Returns plain text.
 */
header('Content-Type: text/plain; charset=utf-8');

$config = require __DIR__ . '/config.php';

echo "=== MikroManager DB diagnostic ===\n\n";

echo "PHP version: " . PHP_VERSION . "\n";
echo "PDO MySQL available: " . (in_array('mysql', PDO::getAvailableDrivers()) ? 'YES' : 'NO') . "\n\n";

echo "DB config:\n";
echo "  host: {$config['db']['host']}\n";
echo "  name: {$config['db']['name']}\n";
echo "  user: {$config['db']['user']}\n";
echo "  password: " . (empty($config['db']['password']) ? 'EMPTY' : '(' . strlen($config['db']['password']) . ' chars)') . "\n\n";

echo "Tenants configured:\n";
foreach ($config['tenants'] as $id => $cfg) {
    echo "  - $id (api_key " . strlen($cfg['api_key']) . " chars)\n";
}
echo "\n";

try {
    $dsn = sprintf(
        'mysql:host=%s;dbname=%s;charset=utf8mb4',
        $config['db']['host'],
        $config['db']['name']
    );
    echo "Trying: $dsn\n";
    $pdo = new PDO($dsn, $config['db']['user'], $config['db']['password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
    echo "✓ Connection successful\n\n";

    echo "Tables in database:\n";
    $tables = $pdo->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN);
    foreach ($tables as $t) echo "  - $t\n";

    if (!in_array('tenants', $tables)) {
        echo "\n⚠ Table 'tenants' MISSING — run schema.sql in phpMyAdmin\n";
    }
    if (!in_array('snapshots', $tables)) {
        echo "⚠ Table 'snapshots' MISSING — run schema.sql in phpMyAdmin\n";
    }

    if (in_array('snapshots', $tables)) {
        $cols = $pdo->query('SHOW COLUMNS FROM snapshots')->fetchAll(PDO::FETCH_COLUMN);
        echo "\nsnapshots columns: " . implode(', ', $cols) . "\n";
        if (!in_array('encrypted', $cols)) {
            echo "⚠ Column 'encrypted' MISSING — run:\n";
            echo "  ALTER TABLE snapshots ADD COLUMN encrypted TINYINT(1) NOT NULL DEFAULT 0;\n";
        }
    }

} catch (Throwable $e) {
    echo "✗ FAILED: " . $e->getMessage() . "\n";
}

echo "\n=== State directory ===\n";
$state = $config['state_dir'] ?? __DIR__ . '/state';
echo "Path: $state\n";
echo "Exists: " . (is_dir($state) ? 'YES' : 'NO') . "\n";
echo "Writable: " . (is_writable($state) ? 'YES' : 'NO (PHP cannot write rate-limit counters)') . "\n";
