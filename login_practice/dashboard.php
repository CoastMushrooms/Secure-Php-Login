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

    <style>
        body {
            font-family: Arial, sans-serif;
            padding: 40px;
            background: #f8f9fa;
        }

        .card {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            max-width: 600px;
            margin: 0 auto;
        }

        .btn-logout {
            padding: 10px 20px;
            background: #dc3545;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 20px;
        }

    </style>

</head>


<body>


<div class="card">

    <h1>
        Welcome to your Dashboard, <?= h($username) ?>!
    </h1>


    <p>
        This is a protected area. Your authentication context was verified safely.
    </p>


    <hr>


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


</body>

</html>