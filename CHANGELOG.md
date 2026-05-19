# Changelog

All notable changes to this project will be documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2026-05-18

### Fixed

- `authClient.emailChallenge.poll()` no longer fires `$sessionSignal` on every poll. The auto-generated client proxy fires the signal on every 2xx, which caused every `useSession()` subscriber to refetch `/get-session` on each pending-poll tick. The client plugin now wraps `poll()` via `getActions` and fires `$sessionSignal` only when the response body carries `status === "completed"`. Honors a `disableSignal: true` opt-out and defers the notify by 10ms to match better-auth's internal race-avoidance.

### Changed

- Bumped `vitest` dev dependency to `^4.0.0` to clear transitive audit vulnerabilities.

## [0.1.2] - 2026-05-17

### Fixed

- `POST /email-challenge/verify` now accepts `application/x-www-form-urlencoded` and `multipart/form-data` bodies, fixing `UNSUPPORTED_MEDIA_TYPE` errors from plain HTML `<form method="POST">` submissions.
- `POST /email-challenge/verify` now redirects HTML clients instead of returning raw JSON:
  - When `approvalPageURL` is set: `302 → ${approvalPageURL}?token=<token>`
  - Otherwise: serves `renderApprovalPage({ state: "approved" })` or the built-in "Sign-in approved" HTML page.
  - JS clients sending `Accept: application/json` still receive the existing JSON contract unchanged.

## [0.1.1] - 2026-05-17

- No runtime changes.
- Updated publishing and release metadata.

## [0.1.0] – 2026-05-16

Initial release.

### Added

- `emailChallenge()` server plugin and `emailChallengeClient()` client plugin
- Endpoints:
  - `POST /sign-in/email-challenge` — start a challenge
  - `GET /email-challenge/verify` — confirmation page (or same-device shortcut)
  - `POST /email-challenge/verify` — flip a pending challenge to approved
  - `POST /email-challenge/verify-otp` — same-device OTP completion (mints a session in this response)
  - `GET /email-challenge/poll` — browser-bound completion
  - `GET /email-challenge/context` — read-only approval context for consumer-hosted pages
- Dedicated `emailChallenge` schema (state machine: `pending → approved → consuming → consumed`, plus `expired` / `canceled`)
- `linkMode` option (`"cross-device"` | `"same-device"` | `"magic-link"`) controlling the email-link click flow
- `approvalPageURL` option for consumer-hosted confirmation pages
- `renderApprovalPage` callback for inline HTML overrides
- `retainConsumedChallenges` option for audit retention
- `cookieName` option to override the default `"email_challenge"` cookie name
- `sendChallengeEmail` integrator callback receiving `url`, `otp`, and approval context
- Security defenses: GET-renders / POST-mutates split (mail-scanner prefetch defense), atomic state CAS, constant-time OTP/binding compare, `callbackURL` rewrite-phishing prevention, uniform `INVALID_TOKEN` responses, strict cookie parser, HMAC-signed cookies
- Tests against `better-auth@1.5.0` (floor) and `latest` via CI matrix
- Supply-chain hardening: `.npmrc` `min-release-age=7` (CI upgrades npm to 11+)
