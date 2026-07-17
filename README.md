# Secure PHP Login

A PHP and MySQL authentication system with login, registration, and a session-protected dashboard. Built to demonstrate common web auth security controls: hashed passwords, CSRF protection, prepared statements, rate limiting, timing-attack mitigation, and audit logging.

## Security Features

| Feature | Details |
|---|---|
| **Password hashing** | Uses `password_hash()` and `password_verify()` (bcrypt) |
| **Timing-attack mitigation** | A dummy `password_verify()` call always runs, even when no matching account exists, so login response time can't be used to guess whether a username is valid |
| **CSRF protection** | Per-session tokens checked with `hash_equals()` on every state-changing POST (login, register, logout) |
| **SQL injection protection** | All queries use PDO prepared statements |
| **XSS protection** | All dynamic output goes through a shared `h()` escaping helper |
| **Session security** | `httponly`, strict-mode, `SameSite=Strict` cookies, session ID regeneration on login, an idle timeout, and full teardown (destroy, expire cookie, regenerate) on logout |
| **Account and IP rate limiting** | Separate thresholds for repeated failures on a single account vs. a single IP, so one doesn't unfairly lock out the other (for example, several users behind the same NAT) |
| **Registration throttling** | A separate per-IP limit on registration attempts |
| **Enumeration resistance** | Registration returns the same message whether the account was created or already existed. A disabled account fails login with the same generic error as a wrong password |
| **Account status** | A `status` column (`active` or `disabled`) lets an account be deactivated without deleting it |
| **Security headers and CSP** | `X-Frame-Options`, `X-Content-Type-Options`, a restrictive `Content-Security-Policy`, HSTS when served over HTTPS, and cache-control headers so sensitive pages aren't cached |
| **Audit logging** | Logins, failures, lockouts, registrations, and logouts are all recorded in an `audit_log` table |

## Requirements

- PHP 8+ with the PDO MySQL extension
- MySQL or MariaDB

## Setup

1. Clone the repo:
   ```bash
   git clone https://github.com/CoastMushrooms/Secure-Php-Login.git
   cd Secure-Php-Login
   ```

2. Create the database and load the schema:
   ```bash
   mysql -u root -p -e "CREATE DATABASE secure_login_db"
   mysql -u root -p secure_login_db < schema.sql
   ```

3. Configure the database connection with environment variables (recommended), or rely on the development defaults in `config.php` (`127.0.0.1` / `secure_login_db` / `root` / no password):
   ```bash
   export DB_HOST=127.0.0.1
   export DB_NAME=secure_login_db
   export DB_USER=root
   export DB_PASS=yourpassword
   ```
   Set `APP_ENV=production` to require these variables instead of falling back to the development defaults.

4. Serve the app, for example with PHP's built-in server:
   ```bash
   php -S localhost:8000
   ```
   Then visit `http://localhost:8000/register.php` to create an account, or `http://localhost:8000/index.php` to sign in.

## File Structure

| File | Purpose |
|---|---|
| `index.php` | Login page: form and flashed error/timeout messages |
| `login.php` | Handles login POST requests: validation, rate limiting, authentication, session setup |
| `register.php` | Registration form and handler: validation, duplicate check, account creation |
| `dashboard.php` | Session-protected page shown after login |
| `logout.php` | CSRF-protected POST endpoint that fully tears down the session |
| `config.php` | Security headers, session configuration, environment-driven DB config, CSRF helpers |
| `inc/db.php` | Creates the shared PDO connection |
| `inc/auth.php` | Core auth helpers: escaping, session and auth checks, CSRF verification, rate limiting, audit logging |
| `schema.sql` | Database schema: `users`, `login_attempts`, `registration_attempts`, `audit_log` |
| `AGENT_SUMMARY.md` | Write-up of the multi-agent workflow used to build and review this project |

## Development Process

This project was built and reviewed through a multi-stage, multi-agent pipeline: an architect agent planned the structure, a developer agent implemented it, and separate reviewer agents audited the code across several rounds, checking each finding against the real code before any fix was applied. See [`AGENT_SUMMARY.md`](AGENT_SUMMARY.md) for the full write-up, including which reported vulnerabilities were confirmed and which turned out to be false positives.
