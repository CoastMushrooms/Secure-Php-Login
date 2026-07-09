<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';

/*
|--------------------------------------------------------------------------
| Output Escaping
|--------------------------------------------------------------------------
*/

function h(string $string): string
{
    return htmlspecialchars($string, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/*
|--------------------------------------------------------------------------
| Username Normalization
|--------------------------------------------------------------------------
*/

function normalize_username(string $username): string
{
    return trim(mb_strtolower($username, 'UTF-8'));
}

/*
|--------------------------------------------------------------------------
| Client IP
|--------------------------------------------------------------------------
*/

function client_ip(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/*
|--------------------------------------------------------------------------
| Authentication
|--------------------------------------------------------------------------
*/

function is_authenticated(): bool
{
    return isset($_SESSION['user_id']);
}

function check_session_timeout(): void
{
    if (!isset($_SESSION['last_activity'])) {
        $_SESSION['last_activity'] = time();
        return;
    }

    if ((time() - $_SESSION['last_activity']) > SESSION_LIFETIME) {

        $_SESSION = [];

        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();

            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params['path'],
                $params['domain'],
                $params['secure'],
                $params['httponly']
            );
        }

        session_destroy();

        header("Location: index.php?timeout=1");
        exit;
    }

    $_SESSION['last_activity'] = time();
}

function require_login(): void
{
    if (!is_authenticated()) {
        header("Location: index.php");
        exit;
    }

    check_session_timeout();
}

/*
|--------------------------------------------------------------------------
| CSRF
|--------------------------------------------------------------------------
*/

function verify_csrf_token(string $token): bool
{
    return isset($_SESSION['csrf_token'])
        && hash_equals($_SESSION['csrf_token'], $token);
}

/*
|--------------------------------------------------------------------------
| Audit Logging
|--------------------------------------------------------------------------
*/

function log_security_event(
    PDO $pdo,
    string $eventType,
    ?string $username = null,
    ?string $details = null
): void {

    try {

        $stmt = $pdo->prepare("
            INSERT INTO audit_log
            (event_type, username, ip_address, details)
            VALUES
            (:event, :username, :ip, :details)
        ");

        $stmt->execute([
            ':event' => $eventType,
            ':username' => $username,
            ':ip' => client_ip(),
            ':details' => $details
        ]);

    } catch (Throwable $e) {
        error_log($e->getMessage());
    }
}

/*
|--------------------------------------------------------------------------
| Login Rate Limiting
|--------------------------------------------------------------------------
*/

function is_login_rate_limited(PDO $pdo, string $username): bool
{
    $ip = client_ip();

    /*
    |--------------------------------------------------------------
    | Account Lockout
    |--------------------------------------------------------------
    */

    $stmt = $pdo->prepare("
        SELECT COUNT(*)
        FROM login_attempts
        WHERE LOWER(username)=LOWER(:username)
        AND attempted_at >
            NOW() - INTERVAL :minutes MINUTE
    ");

    $stmt->bindValue(':username', $username);
    $stmt->bindValue(':minutes', LOCKOUT_TIME_MINUTES, PDO::PARAM_INT);
    $stmt->execute();

    if ($stmt->fetchColumn() >= MAX_ACCOUNT_ATTEMPTS) {

        log_security_event(
            $pdo,
            'account_lockout',
            $username,
            'Account threshold exceeded'
        );

        return true;
    }

    /*
    |--------------------------------------------------------------
    | Global IP Lockout
    |--------------------------------------------------------------
    */

    $stmt = $pdo->prepare("
        SELECT COUNT(*)
        FROM login_attempts
        WHERE ip_address=:ip
        AND attempted_at >
            NOW() - INTERVAL :minutes MINUTE
    ");

    $stmt->bindValue(':ip', $ip);
    $stmt->bindValue(':minutes', LOCKOUT_TIME_MINUTES, PDO::PARAM_INT);
    $stmt->execute();

    if ($stmt->fetchColumn() >= MAX_GLOBAL_IP_ATTEMPTS) {

        log_security_event(
            $pdo,
            'ip_rate_limit',
            $username,
            'Global IP threshold exceeded'
        );

        return true;
    }

    return false;
}

/*
|--------------------------------------------------------------------------
| Failed Login Tracking
|--------------------------------------------------------------------------
*/

function log_failed_login_attempt(PDO $pdo, string $username): void
{
    $stmt = $pdo->prepare("
        INSERT INTO login_attempts
        (ip_address, username)
        VALUES
        (:ip,:username)
    ");

    $stmt->execute([
        ':ip' => client_ip(),
        ':username' => $username
    ]);

    log_security_event(
        $pdo,
        'login_failed',
        $username,
        'Failed authentication'
    );
}

function clear_failed_login_attempts(PDO $pdo, string $username): void
{
    $stmt = $pdo->prepare("
        DELETE FROM login_attempts
        WHERE ip_address=:ip
        OR LOWER(username)=LOWER(:username)
    ");

    $stmt->execute([
        ':ip' => client_ip(),
        ':username' => $username
    ]);
}

/*
|--------------------------------------------------------------------------
| Registration Rate Limiting
|--------------------------------------------------------------------------
*/

function is_registration_rate_limited(PDO $pdo): bool
{
    $stmt = $pdo->prepare("
        SELECT COUNT(*)
        FROM registration_attempts
        WHERE ip_address=:ip
        AND attempted_at >
            NOW() - INTERVAL :minutes MINUTE
    ");

    $stmt->bindValue(':ip', client_ip());
    $stmt->bindValue(':minutes', LOCKOUT_TIME_MINUTES, PDO::PARAM_INT);

    $stmt->execute();

    return $stmt->fetchColumn() >= MAX_REG_ATTEMPTS_PER_IP;
}

function log_registration_attempt(PDO $pdo): void
{
    $stmt = $pdo->prepare("
        INSERT INTO registration_attempts
        (ip_address)
        VALUES
        (:ip)
    ");

    $stmt->execute([
        ':ip' => client_ip()
    ]);

    log_security_event(
        $pdo,
        'registration_attempt',
        null,
        'Registration submitted'
    );
}