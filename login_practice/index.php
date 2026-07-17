<?php
declare(strict_types=1);

require_once 'inc/auth.php';

if (is_authenticated()) {
    header("Location: dashboard.php");
    exit;
}

$error = $_SESSION['login_error'] ?? '';

unset($_SESSION['login_error']);

$timeoutMessage = '';

if (isset($_GET['timeout'])) {
    $timeoutMessage = "Your session expired. Please sign in again.";
}
?>