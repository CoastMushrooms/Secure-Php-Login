<?php
declare(strict_types=1);

require_once 'inc/auth.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: index.php");
    exit;
}

if (
    !isset($_POST['csrf_token']) ||
    !verify_csrf_token($_POST['csrf_token'])
) {
    $_SESSION['login_error'] = "Invalid session token. Please try again.";
    header("Location: index.php");
    exit;
}

$identity = normalize_username($_POST['username'] ?? '');
$password = $_POST['password'] ?? '';

if ($identity === '' || $password === '') {
    $_SESSION['login_error'] = "Please fill in all fields.";
    header("Location: index.php");
    exit;
}

// Bound the identity length before it ever reaches a query or a log line.
// Usernames/emails have no legitimate reason to exceed this length, and
// without a cap an attacker can send arbitrarily large payloads on every
// request (wasted CPU/memory on normalization, bloated audit_log rows, etc.)
if (mb_strlen($identity, 'UTF-8') > 255) {
    $_SESSION['login_error'] = "Invalid username/email or password.";
    header("Location: index.php");
    exit;
}

if (strlen($password) > 128) {
    $_SESSION['login_error'] = "Invalid username/email or password.";
    header("Location: index.php");
    exit;
}

try {

    if (is_login_rate_limited($pdo, $identity)) {

        log_security_event(
            $pdo,
            'login_rate_limited',
            $identity,
            'Rate limit exceeded'
        );

        $_SESSION['login_error'] =
            "Too many login attempts. Please wait "
            . LOCKOUT_TIME_MINUTES .
            " minutes.";

        header("Location: index.php");
        exit;
    }

    $stmt = $pdo->prepare("
        SELECT *
        FROM users
        WHERE LOWER(username)=LOWER(:identity)
           OR LOWER(email)=LOWER(:identity)
        LIMIT 1
    ");

    $stmt->execute([
        ':identity' => $identity
    ]);

    $user = $stmt->fetch();

    $passwordMatches = false;

    if ($user) {
        $passwordMatches = password_verify(
            $password,
            $user['password_hash']
        );
    }

    // Always perform a dummy verification to reduce timing differences.
    password_verify($password, DUMMY_HASH);

    // Account must exist, have the correct password, AND be active.
    // A disabled account is treated identically to a wrong password from
    // the user's point of view - no separate error message - so that
    // account status can never be probed from the login form. The real
    // reason is only visible in the audit log.
    $isActive = $user && ($user['status'] ?? 'active') === 'active';

    $authenticated = $passwordMatches && $isActive;

    if ($user && $passwordMatches && !$isActive) {
        log_security_event(
            $pdo,
            'login_disabled_account',
            $user['username'],
            'Correct credentials supplied for a disabled account'
        );
    }

    if ($authenticated) {

        clear_failed_login_attempts($pdo, $identity);

        session_regenerate_id(true);

        refresh_csrf_token();

        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['last_activity'] = time();

        log_security_event(
            $pdo,
            'login_success',
            $user['username'],
            'Successful authentication'
        );

        header("Location: dashboard.php");
        exit;
    }

    log_failed_login_attempt($pdo, $identity);

    $_SESSION['login_error'] =
        "Invalid username/email or password.";

    header("Location: index.php");
    exit;

} catch (PDOException $e) {

    error_log($e->getMessage());

    log_security_event(
        $pdo,
        'database_error',
        $identity,
        'Login exception'
    );

    $_SESSION['login_error'] =
        "A secure authentication error occurred.";

    header("Location: index.php");
    exit;
}