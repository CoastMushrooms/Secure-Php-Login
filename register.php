<?php
declare(strict_types=1);

require_once 'inc/auth.php';

$errors = [];
$success = "";

// Both the real-success path and the duplicate-account path must show
// this EXACT string. Any difference in wording between the two branches
// lets an attacker tell whether a username/email is already registered.
const REGISTRATION_RESULT_MESSAGE =
    "Registration completed successfully. You may now sign in.";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (
        !isset($_POST['csrf_token']) ||
        !verify_csrf_token($_POST['csrf_token'])
    ) {
        $errors[] = "Invalid session token.";
    } else {

        $username = normalize_username($_POST['username'] ?? '');
        $email = strtolower(trim($_POST['email'] ?? ''));
        $password = $_POST['password'] ?? '';

        /*
        |--------------------------------------------------------------------------
        | Validation
        |--------------------------------------------------------------------------
        */

        if (strlen($username) < 3 || strlen($username) > 50) {
            $errors[] = "Username must be between 3 and 50 characters.";
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Please enter a valid email address.";
        }

        if (strlen($password) < 8) {
            $errors[] = "Password must be at least 8 characters.";
        }

        if (strlen($password) > 20) {
            $errors[] = "Password cannot exceed 20 characters.";
        }

        /*
        | Optional password-strength policy
        */

        if (
            !preg_match('/[A-Z]/', $password) ||
            !preg_match('/[a-z]/', $password) ||
            !preg_match('/[^A-Za-z0-9]/', $password)
        ) {
            $errors[] =
                "Password should include upper-case, lower-case letters and a special character.";
        }

        try {

            if (is_registration_rate_limited($pdo)) {

                log_security_event(
                    $pdo,
                    'registration_rate_limited',
                    $username,
                    'Registration limit exceeded'
                );

                $errors[] =
                    "Too many registration attempts. Please try again later.";
            }

            if (empty($errors)) {

                log_registration_attempt($pdo);

                $stmt = $pdo->prepare("
                    SELECT id
                    FROM users
                    WHERE LOWER(username)=LOWER(:username)
                       OR LOWER(email)=LOWER(:email)
                    LIMIT 1
                ");

                $stmt->execute([
                    ':username' => $username,
                    ':email' => $email
                ]);

                if ($stmt->fetch()) {

                    /*
                    | Preserve account enumeration protection: show the
                    | same success message as a real registration so the
                    | response is indistinguishable from the success path.
                    */

                    log_security_event(
                        $pdo,
                        'registration_duplicate',
                        $username,
                        'Duplicate registration'
                    );

                    $success = REGISTRATION_RESULT_MESSAGE;

                } else {

                    $passwordHash = password_hash(
                        $password,
                        PASSWORD_DEFAULT
                    );

                    $stmt = $pdo->prepare("
                        INSERT INTO users
                        (username,email,password_hash)
                        VALUES
                        (:username,:email,:hash)
                    ");

                    $stmt->execute([
                        ':username' => $username,
                        ':email' => $email,
                        ':hash' => $passwordHash
                    ]);

                    refresh_csrf_token();

                    log_security_event(
                        $pdo,
                        'registration_success',
                        $username,
                        'Account created'
                    );

                    $success = REGISTRATION_RESULT_MESSAGE;
                }
            }

        } catch (PDOException $e) {

            error_log($e->getMessage());

            log_security_event(
                $pdo,
                'registration_error',
                $username,
                'Database exception'
            );

            $errors[] =
                "An unexpected processing error prevented registration.";

            if (APP_ENV !== 'production') {
                $errors[] = "Debug detail: " . $e->getMessage();
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>

<meta charset="UTF-8">

<title>Secure Registration</title>

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
        <span class="eyebrow">Create Account</span>
    </div>

    <div class="card">

        <h1 class="title">Register</h1>
        <p class="subtitle">Create an account to get started.</p>

        <?php foreach ($errors as $error): ?>
        <div class="alert alert-error">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.7"/>
                <path d="M12 7V13" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>
                <circle cx="12" cy="16.2" r="0.9" fill="currentColor"/>
            </svg>
            <span><?= h($error) ?></span>
        </div>
        <?php endforeach; ?>

        <?php if ($success): ?>
        <div class="alert alert-success">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.7"/>
                <path d="M8.5 12.3L10.8 14.6L15.5 9.5" stroke="currentColor" stroke-width="1.7"
                      stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <span><?= h($success) ?></span>
        </div>
        <?php endif; ?>

        <form action="register.php" method="POST" autocomplete="off">

            <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">

            <label for="username">Username</label>
            <div class="field">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <circle cx="12" cy="8" r="3.5" stroke="currentColor" stroke-width="1.7"/>
                    <path d="M4.5 20C5.6 16.3 8.4 14.5 12 14.5C15.6 14.5 18.4 16.3 19.5 20"
                          stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>
                </svg>
                <input
                    type="text"
                    id="username"
                    name="username"
                    value="<?= h($username ?? '') ?>"
                    required
                    maxlength="50"
                    autocomplete="username">
            </div>

            <label for="email">Email Address</label>
            <div class="field">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <rect x="3.5" y="5.5" width="17" height="13" rx="2" stroke="currentColor" stroke-width="1.7"/>
                    <path d="M4.5 7L12 12.5L19.5 7" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                <input
                    type="email"
                    id="email"
                    name="email"
                    value="<?= h($email ?? '') ?>"
                    required
                    autocomplete="off">
            </div>

            <div class="popout" id="emailPopout">
                <div class="popout-inner">
                    <div class="popout-label">A valid email needs:</div>
                    <ul class="requirement-list">
                        <li id="email-req-at">
                            <span class="req-check">
                                <svg class="icon-warn" width="2" height="8" viewBox="0 0 2 8" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <rect x="0" y="0" width="2" height="5.5" rx="1" fill="white"/>
                                    <circle cx="1" cy="7.2" r="1" fill="white"/>
                                </svg>
                                <svg class="icon-check" width="11" height="9" viewBox="0 0 11 9" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M1 4.5L4 7.5L10 1" stroke="white" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </span>
                            <span>An @ symbol</span>
                        </li>
                        <li id="email-req-domain">
                            <span class="req-check">
                                <svg class="icon-warn" width="2" height="8" viewBox="0 0 2 8" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <rect x="0" y="0" width="2" height="5.5" rx="1" fill="white"/>
                                    <circle cx="1" cy="7.2" r="1" fill="white"/>
                                </svg>
                                <svg class="icon-check" width="11" height="9" viewBox="0 0 11 9" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M1 4.5L4 7.5L10 1" stroke="white" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </span>
                            <span>A domain (e.g. example.com)</span>
                        </li>
                        <li id="email-req-nospace">
                            <span class="req-check">
                                <svg class="icon-warn" width="2" height="8" viewBox="0 0 2 8" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <rect x="0" y="0" width="2" height="5.5" rx="1" fill="white"/>
                                    <circle cx="1" cy="7.2" r="1" fill="white"/>
                                </svg>
                                <svg class="icon-check" width="11" height="9" viewBox="0 0 11 9" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M1 4.5L4 7.5L10 1" stroke="white" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </span>
                            <span>No spaces</span>
                        </li>
                    </ul>
                </div>
            </div>

            <label for="password">Password (8–20 characters)</label>
            <div class="field">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <rect x="5" y="10.5" width="14" height="9.5" rx="2" stroke="currentColor" stroke-width="1.7"/>
                    <path d="M8 10.5V7.5C8 5.29 9.79 3.5 12 3.5C14.21 3.5 16 5.29 16 7.5V10.5"
                          stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>
                </svg>
                <input
                    type="password"
                    id="password"
                    name="password"
                    required
                    maxlength="20"
                    autocomplete="new-password">
            </div>

            <div class="popout" id="passwordPopout">
                <div class="popout-inner">
                    <div class="pw-progress">
                        <div class="pw-progress-bar" id="pwProgressBar"></div>
                    </div>
                    <div class="popout-label">Password must include:</div>
                    <ul class="requirement-list">
                        <li id="pw-req-length">
                            <span class="req-check">
                                <svg class="icon-warn" width="2" height="8" viewBox="0 0 2 8" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <rect x="0" y="0" width="2" height="5.5" rx="1" fill="white"/>
                                    <circle cx="1" cy="7.2" r="1" fill="white"/>
                                </svg>
                                <svg class="icon-check" width="11" height="9" viewBox="0 0 11 9" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M1 4.5L4 7.5L10 1" stroke="white" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </span>
                            <span>8–20 characters</span>
                        </li>
                        <li id="pw-req-upper">
                            <span class="req-check">
                                <svg class="icon-warn" width="2" height="8" viewBox="0 0 2 8" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <rect x="0" y="0" width="2" height="5.5" rx="1" fill="white"/>
                                    <circle cx="1" cy="7.2" r="1" fill="white"/>
                                </svg>
                                <svg class="icon-check" width="11" height="9" viewBox="0 0 11 9" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M1 4.5L4 7.5L10 1" stroke="white" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </span>
                            <span>An uppercase letter (A–Z)</span>
                        </li>
                        <li id="pw-req-lower">
                            <span class="req-check">
                                <svg class="icon-warn" width="2" height="8" viewBox="0 0 2 8" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <rect x="0" y="0" width="2" height="5.5" rx="1" fill="white"/>
                                    <circle cx="1" cy="7.2" r="1" fill="white"/>
                                </svg>
                                <svg class="icon-check" width="11" height="9" viewBox="0 0 11 9" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M1 4.5L4 7.5L10 1" stroke="white" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </span>
                            <span>A lowercase letter (a–z)</span>
                        </li>
                        <li id="pw-req-special">
                            <span class="req-check">
                                <svg class="icon-warn" width="2" height="8" viewBox="0 0 2 8" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <rect x="0" y="0" width="2" height="5.5" rx="1" fill="white"/>
                                    <circle cx="1" cy="7.2" r="1" fill="white"/>
                                </svg>
                                <svg class="icon-check" width="11" height="9" viewBox="0 0 11 9" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M1 4.5L4 7.5L10 1" stroke="white" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </span>
                            <span>A special character (!@#$%...)</span>
                        </li>
                    </ul>
                </div>
            </div>

            <button type="submit" class="submit">Create Account</button>

        </form>

        <div class="foot-note">
            Already have an account? <a href="index.php">Back to Login</a>
        </div>

    </div>
</div>

<script src="register.js" defer></script>

</body>
</html>