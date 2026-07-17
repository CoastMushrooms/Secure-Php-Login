@echo off
REM Starts PHP built-in server and opens the app in the default browser.
setlocal

REM Start PHP server in a new window using the project root as document root
start "" php -S 127.0.0.1:8000 -t "%~dp0"

REM Wait briefly for server to start
timeout /t 1 >nul

REM Open default browser to the login page
start "" "http://127.0.0.1:8000/index.php"

endlocal
