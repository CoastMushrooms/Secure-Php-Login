<?php
declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Security Headers
|--------------------------------------------------------------------------
*/

header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("X-XSS-Protection: 0");

header(
    "Content-Security-Policy: ".
    "default-src 'self'; ".
    "script-src 'self'; ".
    "style-src 'self'; ".
    "img-src 'self' data:; ".
    "object-src 'none'; ".
    "base-uri 'self'; ".
    "frame-ancestors 'none'; ".
    "form-action 'self';"
);

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

/*
|--------------------------------------------------------------------------
| HTTPS Detection
|--------------------------------------------------------------------------
|
| Only trust HTTP_X_FORWARDED_PROTO if your reverse proxy is trusted.
|
*/

$isHttps =
    (
        !empty($_SERVER['HTTPS']) &&
        $_SERVER['HTTPS'] !== 'off'
    )
    ||
    (
        !empty($_SERVER['HTTP_X_FORWARDED_PROTO']) &&
        $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https'
    );

if ($isHttps) {
    header(
        "Strict-Transport-Security: max-age=31536000; includeSubDomains"
    );
}

/*
|--------------------------------------------------------------------------
| Secure Session Configuration
|--------------------------------------------------------------------------
*/

ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.use_strict_mode', '1');

if ($isHttps) {
    ini_set('session.cookie_secure', '1');
}

define('SESSION_LIFETIME', 1800); // 30 minutes idle timeout

if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_lifetime' => 0,
        'cookie_path'     => '/',
        'cookie_domain'   => '',
        'cookie_secure'   => $isHttps,
        'cookie_httponly' => true,
        'cookie_samesite' => 'Strict',
    ]);
}

/*
|--------------------------------------------------------------------------
| Session Activity Tracking
|--------------------------------------------------------------------------
*/

if (!isset($_SESSION['created'])) {
    $_SESSION['created'] = time();
}

if (!isset($_SESSION['last_activity'])) {
    $_SESSION['last_activity'] = time();
}

/*
|--------------------------------------------------------------------------
| Database Configuration
|--------------------------------------------------------------------------
|
| For development, fallback values are allowed.
| Set APP_ENV=production to require environment variables.
|
*/

$appEnv = getenv('APP_ENV') ?: 'development';

$dbHost = getenv('DB_HOST');
$dbName = getenv('DB_NAME');
$dbUser = getenv('DB_USER');
$dbPass = getenv('DB_PASS');

if ($appEnv === 'production') {

    if (!$dbHost || !$dbName || !$dbUser) {
        error_log("CRITICAL: Missing production database configuration.");
        http_response_code(500);
        exit("Server configuration error.");
    }

} else {

    $dbHost = $dbHost ?: '127.0.0.1';
    $dbName = $dbName ?: 'secure_login_db';
    $dbUser = $dbUser ?: 'root';
    $dbPass = ($dbPass !== false) ? $dbPass : '';

}

define('DB_HOST', $dbHost);
define('DB_NAME', $dbName);
define('DB_USER', $dbUser);
define('DB_PASS', $dbPass);

/*
|--------------------------------------------------------------------------
| Security Configuration
|--------------------------------------------------------------------------
*/

define('MAX_ACCOUNT_ATTEMPTS', 5);

define('MAX_GLOBAL_IP_ATTEMPTS', 20);

define('MAX_REG_ATTEMPTS_PER_IP', 5);

define('LOCKOUT_TIME_MINUTES', 15);

/*
|--------------------------------------------------------------------------
| Dummy Password Hash
|--------------------------------------------------------------------------
|
| Used to equalize password_verify() timing when a user does not exist.
|
*/

define(
    'DUMMY_HASH',
    '$2y$10$K9vBCw82gctqH6B4OEnXU.C6g4jXpESF6yC9wHwB4WlH/oWh6gSme'
);

/*
|--------------------------------------------------------------------------
| CSRF Helpers
|--------------------------------------------------------------------------
*/

function refresh_csrf_token(): void
{
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (empty($_SESSION['csrf_token'])) {
    refresh_csrf_token();
}