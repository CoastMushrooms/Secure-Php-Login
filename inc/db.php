<?php
declare(strict_types=1);

require_once __DIR__ . '/../config.php';


try {

    $dsn =
        "mysql:host=" . DB_HOST .
        ";dbname=" . DB_NAME .
        ";charset=utf8mb4";


    $options = [

        PDO::ATTR_ERRMODE =>
            PDO::ERRMODE_EXCEPTION,

        PDO::ATTR_DEFAULT_FETCH_MODE =>
            PDO::FETCH_ASSOC,

        PDO::ATTR_EMULATE_PREPARES =>
            false,

        PDO::ATTR_TIMEOUT =>
            5,

    ];


    $pdo = new PDO(
        $dsn,
        DB_USER,
        DB_PASS,
        $options
    );


} catch (PDOException $e) {


    error_log(
        "Database initialization error: "
        . $e->getMessage()
    );


    http_response_code(500);

    exit(
        "A secure platform connection error occurred."
    );

}