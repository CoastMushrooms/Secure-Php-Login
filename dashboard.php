<?php
declare(strict_types=1);

require_once 'inc/auth.php';

require_login();

$_SESSION['last_activity'] = time();

$username = $_SESSION['username'] ?? 'User';

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <title>Dashboard</title>

    <link rel="stylesheet" href="style.css">

</head>


<body>


<div class="dashboard-shell">

    <div class="card">

        <h1 class="dashboard-greeting">
            Welcome to your Dashboard, <?= h($username) ?>!
        </h1>

        <p class="dashboard-note">
            This is a protected area. Your authentication context was verified safely.
        </p>

        <hr class="divider">

        <form action="logout.php" method="POST">

            <input
                type="hidden"
                name="csrf_token"
                value="<?= h($_SESSION['csrf_token']) ?>"
            >

            <button type="submit" class="btn-logout">
                Secure Sign Out
            </button>

        </form>

    </div>

</div>


</body>

</html>