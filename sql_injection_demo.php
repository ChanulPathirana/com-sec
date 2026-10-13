<?php
/*
 * CS3053 - Program Vulnerabilities - Part 3
 * Single-file PHP + SQLite web application (LOCAL EDUCATIONAL DEMO ONLY).
 *
 * DATABASE CONSTRUCTION INSTRUCTIONS:
 * 1. Install PHP with its PDO SQLite driver (on Ubuntu: sudo apt install php-cli php-sqlite3).
 * 2. Run: php -S 127.0.0.1:8000
 * 3. Open: http://127.0.0.1:8000/sql_injection_demo.php
 * 4. This script automatically creates sql_injection_demo.sqlite in its folder.
 *    It executes the equivalent of:
 *
 *    CREATE TABLE IF NOT EXISTS users (
 *        id INTEGER PRIMARY KEY AUTOINCREMENT,
 *        username TEXT NOT NULL UNIQUE,
 *        password TEXT NOT NULL
 *    );
 *    INSERT OR IGNORE INTO users(username, password) VALUES ('student', 'test123');
 *
 * Reset: stop the server and delete sql_injection_demo.sqlite.
 * The password is intentionally plaintext ONLY to simplify the classroom demonstration.
 * Real applications must use password_hash() and password_verify(), plus rate limits.
 * Do not deploy the vulnerable endpoint on a public server.
 *
 * TEST CASES (both forms):
 *   username student, password test123: authentication succeeds.
 *   username student, password wrong: authentication fails.
 *   username ' OR 1=1 --  , password anything:
 *     vulnerable form authenticates incorrectly; secure form rejects it.
 */

declare(strict_types=1);

function escapeHtml(string $text): string {
    return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$message = '';
$mode = '';
$username = '';
$password = '';
$error = '';

try {
    if (!extension_loaded('pdo_sqlite')) {
        throw new RuntimeException('PDO SQLite is missing. Install it using: sudo apt install php-sqlite3');
    }

    $db = new PDO('sqlite:' . __DIR__ . '/sql_injection_demo.sqlite');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL)');
    $db->exec("INSERT OR IGNORE INTO users (username, password) VALUES ('student', 'test123')");

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $mode = (string)($_POST['mode'] ?? '');
        $username = (string)($_POST['username'] ?? '');
        $password = (string)($_POST['password'] ?? '');

        if ($mode === 'vulnerable') {
            /* PART 1: VULNERABLE SQL INJECTION EXAMPLE
             * User-controlled values are inserted directly into SQL text.
             * An input such as ' OR 1=1 --  changes the query's meaning.
             */
            $sql = "SELECT id FROM users WHERE username = '$username' AND password = '$password' LIMIT 1";
            $row = $db->query($sql)->fetch(PDO::FETCH_ASSOC);
            $message = $row ? 'VULNERABLE login: accepted' : 'VULNERABLE login: rejected';
        } elseif ($mode === 'secure') {
            /* PART 2: SQL INJECTION PREVENTION
             * Parameterized SQL keeps input as data, never SQL instructions.
             */
            $statement = $db->prepare('SELECT id FROM users WHERE username = :username AND password = :password LIMIT 1');
            $statement->execute([':username' => $username, ':password' => $password]);
            $row = $statement->fetch(PDO::FETCH_ASSOC);
            $message = $row ? 'SECURE login: accepted' : 'SECURE login: rejected';
        } else {
            $message = 'Choose a login mode.';
        }
    }
} catch (Throwable $exception) {
    $error = $exception->getMessage();
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CS3053 - SQL Injection Demonstration</title>
</head>
<body>
<h1>SQL Injection Login Demo</h1>
<p>Test account: student / test123</p>
<form method="post">
<p><label>Username: <input name="username" value="<?= escapeHtml($username) ?>" required></label></p>
<p><label>Password: <input name="password" type="text" value="<?= escapeHtml($password) ?>" required></label></p>
<button name="mode" value="vulnerable" type="submit">Vulnerable login</button>
<button name="mode" value="secure" type="submit">Secure login</button>
</form>
<?php if ($message !== ''): ?>
<p role="status"><?= escapeHtml($message) ?></p>
<?php endif; ?>
<?php if ($error !== ''): ?>
<p role="alert">Error: <?= escapeHtml($error) ?></p>
<?php endif; ?>
<h2>How to test</h2>
<p>Use username <code>' OR 1=1 -- </code> (include a trailing space) and any password.
The vulnerable query may accept this login; the parameterized query rejects it.</p>
</body>
</html>
