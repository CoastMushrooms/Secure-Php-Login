# Secure PHP Login

A PHP + MySQL authentication system (login, registration, session-protected dashboard) built as a practical demonstration of common web auth security controls: hashed passwords, CSRF protection, prepared statements, rate limiting, timing-attack mitigation, and audit logging.

## Security Features
 
| Feature | Details |
|---|---|
| **Password hashing** | Via `password_hash()` / `password_verify()` (bcrypt) |
| **Timing-attack mitigation** | A dummy `password_verify()` call always runs, even when no matching account exists, so login response time doesn't leak whether a username is valid |
| **CSRF protection** | Per-session tokens checked with `hash_equals()` on every state-changing POST (login, register, logout) |
| **SQL injection protection** | All queries use PDO prepared statements |
| **XSS protection** | All dynamic output passed through a shared `h()` escaping helper |
| **Session security** | `httponly`, `strict`-mode, `SameSite=Strict` cookies, ID regeneration on login, idle timeout, and full session teardown (destroy + cookie expiry + regenerate) on logout |
| **Account + IP rate limiting** | Separate thresholds for repeated failures against a single account vs. a single IP, so one doesn't unfairly lock out the other (e.g. a NAT full of users behind one IP) |
| **Registration throttling** | A separate per-IP limit on registration attempts |
| **Enumeration resistance** | Registration returns an identical message whether the account was created or already existed; disabled accounts fail login with the same generic error as a wrong password |
| **Account status** | A `status` (`active`/`disabled`) column lets an account be deactivated without deleting it |
| **Security headers & CSP** | `X-Frame-Options`, `X-Content-Type-Options`, a restrictive `Content-Security-Policy`, HSTS (when served over HTTPS), and cache-control headers to stop sensitive pages being cached |
| **Audit logging** | Logins, failures, lockouts, registrations, and logouts are all recorded to an `audit_log` table |

## Requirements

- PHP 8+ with the PDO MySQL extension
- MySQL or MariaDB

## Setup

1. Clone the repo:
   ```bash
   git clone https://github.com/CoastMushrooms/Secure-Php-Login.git
   cd Secure-Php-Login/login_practice
   ```

2. Create the database and load the schema:
   ```bash
   mysql -u root -p -e "CREATE DATABASE secure_login_db"
   mysql -u root -p secure_login_db < schema.sql
   ```

3. Configure the database connection via environment variables (recommended), or rely on the development defaults in `config.php` (`127.0.0.1` / `secure_login_db` / `root` / no password):
   ```bash
   export DB_HOST=127.0.0.1
   export DB_NAME=secure_login_db
   export DB_USER=root
   export DB_PASS=yourpassword
   ```
   Set `APP_ENV=production` to require these variables to be set explicitly rather than falling back to development defaults.

4. Serve the app, e.g. with PHP's built-in server:
   ```bash
   php -S localhost:8000
   ```
   Then visit `http://localhost:8000/register.php` to create an account.

## Known gap

`index.php` currently contains only the login-page logic (redirect-if-authenticated, reading the flashed error/timeout message). It doesn't yet render an actual login form. `login.php` and the CSRF/rate-limiting logic behind it are fully implemented and working; what's missing is the HTML template that would POST to it (see `register.php` for the pattern this would follow). Registration, the dashboard, and logout all have complete UI.

## File Structure

| File | Purpose |
|---|---|
| `index.php` | Login page entry point (form template not yet implemented) |
| `login.php` | Handles login POST requests: validation, rate limiting, authentication, session setup |
| `register.php` | Registration form + handler: validation, duplicate-check, account creation |
| `dashboard.php` | Session-protected page shown after login |
| `logout.php` | CSRF-protected POST endpoint that fully tears down the session |
| `config.php` | Security headers, session configuration, environment-driven DB config, CSRF helpers |
| `inc/db.php` | Creates the shared PDO connection |
| `inc/auth.php` | Core auth helpers: escaping, session/auth checks, CSRF verification, rate limiting, audit logging |
| `schema.sql` | Database schema: `users`, `login_attempts`, `registration_attempts`, `audit_log` |
| `AGENT_SUMMARY.md` | Write-up of the multi-agent workflow used to build and security-review this project |

## Development Process

This project was built and security-reviewed through a multi-stage, multi-agent pipeline. An architect agent planned the structure, a developer agent implemented it, and multiple independent reviewer agents audited the code across several rounds, triaging findings against the real code before applying fixes. See [`AGENT_SUMMARY.md`](AGENT_SUMMARY.md) for the full write-up, including which reported vulnerabilities were confirmed and which turned out to be false positives.
