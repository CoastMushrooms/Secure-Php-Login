<?php
declare(strict_types=1);

require_once 'inc/auth.php';


if ($_SERVER['REQUEST_METHOD'] !== 'POST') {

    header("Location: dashboard.php");
    exit;

}


if (
    !isset($_POST['csrf_token']) ||
    !verify_csrf_token($_POST['csrf_token'])
) {

    header("Location: dashboard.php");
    exit;

}


if (is_authenticated()) {

    log_security_event(
        $pdo,
        'logout',
        $_SESSION['username'] ?? null,
        'User logged out'
    );

}


$_SESSION = [];


if (ini_get("session.use_cookies")) {

    $params = session_get_cookie_params();

    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params["path"],
        $params["domain"],
        $params["secure"],
        $params["httponly"]
    );

}


session_destroy();


// Prevent reuse of old session identifiers
session_start();

session_regenerate_id(true);

session_destroy();


header("Location: index.php");

exit;