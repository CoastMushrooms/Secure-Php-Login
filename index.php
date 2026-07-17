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
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign In</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="auth-shell">

        <div class="brand">
            <div class="brand-icon">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 2L4 5.5V11C4 16 7.4 20.6 12 22C16.6 20.6 20 16 20 11V5.5L12 2Z"
                          stroke="white" stroke-width="1.7" stroke-linejoin="round"/>
                    <path d="M9 12L11 14L15.5 9.5" stroke="white" stroke-width="1.7"
                          stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </div>
            <span class="eyebrow">Secure Access</span>
        </div>

        <div class="card">

            <h1 class="title">Welcome back</h1>
            <p class="subtitle">Sign in to continue to your dashboard.</p>

            <?php if ($timeoutMessage): ?>
                <div class="alert alert-info">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.7"/>
                        <path d="M12 8V13" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>
                        <circle cx="12" cy="16" r="0.9" fill="currentColor"/>
                    </svg>
                    <span><?= h($timeoutMessage) ?></span>
                </div>
            <?php endif; ?>

            <?php if ($error): ?>
                <div class="alert alert-error">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.7"/>
                        <path d="M12 7V13" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>
                        <circle cx="12" cy="16.2" r="0.9" fill="currentColor"/>
                    </svg>
                    <span><?= h($error) ?></span>
                </div>
            <?php endif; ?>

            <form action="login.php" method="POST">
                <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">

                <label for="username">Username or Email</label>
                <div class="field">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <circle cx="12" cy="8" r="3.5" stroke="currentColor" stroke-width="1.7"/>
                        <path d="M4.5 20C5.6 16.3 8.4 14.5 12 14.5C15.6 14.5 18.4 16.3 19.5 20"
                              stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>
                    </svg>
                    <input type="text" id="username" name="username" required maxlength="255" autocomplete="username">
                </div>

                <label for="password">Password</label>
                <div class="field">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <rect x="5" y="10.5" width="14" height="9.5" rx="2" stroke="currentColor" stroke-width="1.7"/>
                        <path d="M8 10.5V7.5C8 5.29 9.79 3.5 12 3.5C14.21 3.5 16 5.29 16 7.5V10.5"
                              stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>
                    </svg>
                    <input type="password" id="password" name="password" required maxlength="20" autocomplete="current-password">
                </div>

                <button type="submit" class="submit">Sign In</button>
            </form>

            <div class="foot-note">
                Don't have an account? <a href="register.php">Register</a>
            </div>

        </div>
    </div>
</body>
</html>