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

        if (strlen($password) > 128) {
            $errors[] = "Password cannot exceed 128 characters.";
        }

        /*
        | Optional password-strength policy
        */

        if (
            !preg_match('/[A-Z]/', $password) ||
            !preg_match('/[a-z]/', $password) ||
            !preg_match('/[0-9]/', $password)
        ) {
            $errors[] =
                "Password should include upper-case, lower-case and a number.";
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
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>

<meta charset="UTF-8">

<title>Secure Registration</title>

<style>

body{
    font-family:Arial,sans-serif;
    background:#f4f4f9;
    padding:50px;
}

.form-container{
    max-width:400px;
    margin:0 auto;
    background:#fff;
    padding:30px;
    border-radius:8px;
    box-shadow:0 4px 15px rgba(0,0,0,.1);
}

.error{
    color:#d9534f;
}

.success{
    color:#28a745;
}

input{
    width:100%;
    padding:10px;
    margin:10px 0;
    border:1px solid #ccc;
    border-radius:4px;
    box-sizing:border-box;
}

button{
    width:100%;
    padding:10px;
    background:#28a745;
    color:white;
    border:none;
    border-radius:4px;
    cursor:pointer;
}

</style>

</head>
<body>

<div class="form-container">

<h2>Register</h2>

<?php foreach ($errors as $error): ?>
<p class="error"><?= h($error) ?></p>
<?php endforeach; ?>

<?php if ($success): ?>
<p class="success"><?= h($success) ?></p>
<?php endif; ?>

<form action="register.php" method="POST">

<input
type="hidden"
name="csrf_token"
value="<?= h($_SESSION['csrf_token']) ?>">

<label>Username</label>

<input
type="text"
name="username"
value="<?= h($username ?? '') ?>"
required
maxlength="50">

<label>Email Address</label>

<input
type="email"
name="email"
value="<?= h($email ?? '') ?>"
required>

<label>Password (8–128 characters)</label>

<input
type="password"
name="password"
required
maxlength="128">

<button type="submit">
Create Account
</button>

</form>

<p style="margin-top:15px;text-align:center;">
<a href="index.php">Back to Login</a>
</p>

</div>

</body>
</html>