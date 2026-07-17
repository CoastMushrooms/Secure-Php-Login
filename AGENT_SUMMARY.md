# Building a Secure PHP Authentication System with a Multi-Agent Workflow

## Overview

This project was built using an **orchestrated, multi-agent workflow** rather than a single prompt-to-code request. An open-source agent framework (Hermes Agent) was used to define the plan and delegate roles, and several different AI models were then assigned distinct responsibilities with their outputs fed into one another in a structured pipeline. The goal was not just to generate working PHP code, but to demonstrate how multiple agents, each with a different job, can collaborate, challenge each other's work, and converge on a more secure result than any single pass would produce.

## Tooling: Standing Up Hermes Agent

The framework used to kick off the orchestration was [Hermes Agent](https://github.com/NousResearch/hermes-agent), a mainstream open-source, self-hostable agent framework that supports pluggable model providers, tool use, and a bundled skills library (over 70 skills covering everything from GitHub workflows to code review to debugging).

Rather than using the hosted Nous Portal (which required billing), Hermes was configured with a **bring-your-own-key** setup:

- Ran the installer's setup wizard and selected the "Full setup" path instead of the default hosted-portal option
- Kept the terminal backend local and skipped the messaging/gateway integration (Telegram/Discord), since neither was needed for this task
- Added a custom OpenAI-compatible provider pointed at Groq's endpoint (`https://api.groq.com/openai/v1`), authenticated with a personal Groq API key
- Hit a `413 Request too large` error on the first run (Groq's free-tier token-per-minute limit (8,000 TPM) couldn't handle the large `AGENTS.md` context file Hermes was attaching automatically)
- Worked around this by switching providers to Hugging Face's inference router and selecting a coding-oriented model (`Qwen/Qwen3-Coder-Next`) instead of the larger, context-hungry model that had triggered the rate limit

With Hermes running locally against a live model, it was used as the **first agent in the pipeline** the architect/orchestrator that produced the initial project plan.

## The Workflow

```
   Hermes Agent (Architect / Orchestrator)
          |
          v
   Gemini (Developer)
          |
          v
   Claude (Security Reviewer)
          |
          v
   Developer Fixes Applied
          |
          v
   DeepSeek (Independent Final Audit)
          |
          v
   Gemini (Security Triage)
          |
          v
   Claude (Ground-Truth Verification & Remediation)
          |
          v
   Release-Ready Codebase
```

Each stage had a distinct job, and each agent only saw the output of the previous stage, mimicking how a real engineering team hands work between an architect, a builder, and independent reviewers.

## Stage 1 — Architecture (Hermes Agent)

Hermes was prompted to act as the lead architect and produce a plan for a secure PHP login application: a file structure (`index.php`, `login.php`, `register.php`, `logout.php`, `dashboard.php`, `config.php`, `inc/auth.php`, `inc/db.php`), a list of required security measures (password hashing, CSRF protection, prepared statements, XSS escaping, session security, rate limiting, HTTPS enforcement), a minimal database schema, a list of core functions, and a testing checklist. This plan became the shared spec that every later agent worked from.

## Stage 2 — Implementation (Gemini)

Hermes's plan was handed to Gemini with instructions to act as the lead developer and implement it fully. Gemini produced a first complete implementation along with a database schema and a stated set of assumptions (e.g., using PDO with MySQL, embedding minimal CSS, regenerating session IDs on login).

## Stage 3 — Independent Security Review

Rather than accepting the first version at face value, the code was handed to a **separate agent acting purely as an auditor** with no knowledge of the design intent, only the code itself. This produced a structured vulnerability list, including:

- User enumeration via differing registration messages
- Uncaught database exceptions leaking internal errors
- IP-only rate limiting that botnets could bypass and NAT users could suffer from
- A GET-based logout vulnerable to forced-logout CSRF
- Contradictory HTTPS/cookie-security logic
- Missing password length caps (a cheap DoS vector against bcrypt)
- Hardcoded database credentials
- Missing security headers
- No email verification

## Stage 4 — Remediation Pass

The findings were fed back to a developer agent with explicit instructions to fix each issue. This produced a hardened second version of every file: environment-driven credentials, global security headers, consistent HTTPS detection behind reverse proxies, password length limits, split account/IP rate-limit tracking, a registration throttle, and CSRF-protected logout via POST.

## Stage 5 — A Second, Independent Audit (Adversarial Loop)

To avoid a single agent simply approving its own fixes, the hardened code was sent to **yet another independent auditor** with a stricter mandate: *find vulnerabilities, do not suggest fixes yet.* This surfaced subtler issues that only appear once you trace how functions interact across files, such as:

- A timing side-channel where `password_verify()` only runs when a user is found, making nonexistent usernames measurably faster to reject
- Case-sensitivity mismatches between how the rate limiter logs attempts and how the login query matches accounts (`admin` vs `Admin` vs `ADMIN`)
- A shared-IP lockout query (`ip_address = :ip OR username = :username`) that could lock out every user on a corporate NAT if one attacker targeted it
- No rate limiting on the registration endpoint at all

## Stage 6 — Second Remediation

These findings drove another round of fixes: a dummy `password_verify()` call against a fixed hash to equalize timing regardless of whether the account exists, `LOWER()`-normalized rate-limit queries, a split between per-account and global per-IP thresholds (so a NAT-wide block requires a much higher attempt count than a single-account block), and a dedicated `registration_attempts` table with its own throttle.

## Stage 7 — Final Independent Audit (DeepSeek)

A third-party model, DeepSeek, was brought in for a **final, adversarial audit** with a strict brief: assess authentication, session handling, CSRF, XSS, SQL injection, infrastructure configuration, and abuse resistance, and rate production-readiness. It returned 16 findings and an overall score of 6.5/10, flagging items ranging from session-destruction order in `logout.php` to missing email verification and audit-log retention.

## Stage 8 — Triage Against Ground Truth

Rather than blindly implementing all 16 findings, the report was triaged **against the actual code**, not just the audit's prose, which matters because a single-pass auditor working from a diff or summary can flag things that don't hold up once you check the real call graph. For example:

| Finding | Verdict |
|---|---|
| Logout session destroy/regenerate "vulnerability" | **False positive** — `session_destroy()` is synchronous; no exploitable window exists |
| Uncaught DB exception in login | **False positive** — `log_security_event()` already wraps its own calls in `try/catch` |
| Duplicate-registration message leak | **Confirmed**, but for a different reason than stated — the two response strings weren't byte-identical |
| Missing username length cap | **Confirmed** — cheap, real fix |
| Missing account status/disable mechanism | **Confirmed** — no way to deactivate a compromised account without deleting the row |
| Email verification / password reset | **Feature gaps**, not vulnerabilities in the code as written |

This step turned a generic 16-item audit into a small, prioritized list of changes actually worth making, and avoided introducing churn (like arbitrary `usleep()` delays) that would have looked like a "fix" without meaningfully improving security.

## Stage 9 — Final Fixes

The confirmed, real issues were implemented as targeted diffs:

- Registration success and duplicate-account messages made byte-identical, closing the enumeration gap
- A `status` (`active`/`disabled`) column added to `users`, checked at login but surfaced only as the same generic "invalid credentials" message so it can't become a new enumeration vector
- A username length cap added to `login.php`, mirroring the existing password-length guard
- A documented migration path (`ALTER TABLE`) for upgrading an existing database without breaking `CREATE TABLE IF NOT EXISTS`

## Repository Organization

The finished application was published as its **own standalone repository**, separate from the Hermes Agent installation used to run the architect stage. Hermes is the toolchain (comparable to an IDE or CLI) while the secure login page is the deliverable the assignment actually asked for, so the two were kept apart:

- `hermes-agent` — the agent framework itself, left as-is
- `secure-php-login` — the standalone PHP application, with its own `README.md` documenting the multi-agent workflow, the security features implemented, and the roles each agent played

No local Hermes configuration, `.env` files, or API keys were included in the application repository, only the PHP source, schema, and documentation of the process.

## Why This Approach

This project demonstrates **agent orchestration using an open-source framework**: an agent framework (Hermes) plans and delegates, one model builds, independent models adversarially review, and a final triage step separates real vulnerabilities from false positives and feature gaps before anything is merged. That loop that plans, builds, audits, fixes, re-audits, triages, fixes again, produced a materially better result than any single agent's first pass, including catching issues (like the timing side-channel and the shared-IP lockout) that only became visible once agents were specifically tasked with breaking the previous stage's work.
