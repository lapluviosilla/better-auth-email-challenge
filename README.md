# better-auth-email-challenge

A [Better Auth](https://better-auth.com) plugin implementing a single passwordless **email challenge** authentication primitive: one challenge, two completion paths (clickable approval link **or** OTP), safe for same-device _and_ cross-device sign-in.

> **Status: pre-1.0.** The API is stable enough that we'd ship it in production today, but minor versions may still adjust option shapes. Pin a version in your `package.json` and read the CHANGELOG before bumping. We are currently using it in one production application.

> This plugin is **not** `magic-link` + `email-otp` glued together. It introduces a single underlying challenge that the email proves ownership of, while session issuance stays bound to the originating browser. That separation is what makes the cross-device flow safe.

## Why

Better Auth's existing passwordless plugins force a tradeoff:

| Plugin       | Strength           | Weakness                                                                                                               |
| ------------ | ------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `magic-link` | Frictionless       | Same-device only in practice — clicking the link on a different device signs in _that_ device, not the one that asked. |
| `email-otp`  | Works cross-device | More friction; the user has to copy a code.                                                                            |

Real users open mail on a different device than the browser they're signing in on (desktop browser → phone mail, Arc → Apple Mail, etc.). `email-challenge` sends a single email that supports both flows and always routes the resulting session to the **originating browser**.

## How it works

```
   Browser                Server               Email-recipient device
      │                     │                            │
      │ POST /sign-in/email-challenge { email }          │
      ├────────────────────►│                            │
      │ ◄──── 200 { challengeId, expiresAt }             │
      │       Set-Cookie: email_challenge=<id+secret>    │
      │                     │   sendChallengeEmail(...)  │
      │                     ├───────────────────────────►│
      │                     │                            │
      │ GET /email-challenge/poll (every Ns)             │
      ├────────────────────►│   status: "pending"        │
      │                     │                            │
      │                     │   GET  /email-challenge/verify?token=...
      │                     │◄───────────────────────────│  (user clicks link)
      │                     │   → renders Confirm page   │
      │                     │     (no state change)      │
      │                     │                            │
      │                     │   POST /email-challenge/verify { token }
      │                     │◄───────────────────────────│  (user clicks Confirm)
      │                     │   → status: "approved"     │
      │                     │                            │
      │ GET /email-challenge/poll                        │
      ├────────────────────►│   status: "completed"      │
      │ ◄── 200 { user, session }                        │
      │       Set-Cookie: better-auth.session_token=...  │
```

The approval click **never mints a session directly** — it only flips a status field. The originating browser, identified by its signed `email_challenge` cookie, is the only party that can complete the session exchange. The approval is also split across a GET (renders a "Confirm sign-in" page) and a POST (the actual state transition), so mail-security gateways that follow GETs cannot advance the flow on their own — only an explicit user click can.

The diagram shows the default cross-device flow. **Same-device clicks** (same browser as the polling tab) skip the Confirm page automatically — the cookie binding is the user's affirmation. See [Auth paths](#auth-paths) for the full picture.

## Install

```bash
pnpm add better-auth-email-challenge
# or npm / yarn / bun
```

Requires Better Auth `^1.5.0` as a peer dependency. (`zod ^4.0.0` comes in transitively via Better Auth.) Tested in CI against both `1.5.0` (the floor) and `latest`.

**Bundle size:** ~30 KB raw / **~7.5 KB gzip** for the full plugin (server + client). The client portion that actually ships to browsers is **314 bytes gzipped** — the rest is server-only and never crosses the network on a user request.

## Quick start

```ts
// lib/auth.ts
import { betterAuth } from "better-auth";
import { emailChallenge } from "better-auth-email-challenge";

export const auth = betterAuth({
  database: /* your adapter */,
  plugins: [
    emailChallenge({
      async sendChallengeEmail({ email, url, otp, challenge }) {
        // Render however you like — React Email, plain HTML, Postmark
        // templates, whatever. Both `url` and `otp` are independent
        // primitives; include either or both depending on the UX you want.
        // Remember to HTML-escape `challenge.userAgent`/`challenge.ipAddress`
        // if you embed them directly (they originate from request headers).
        await myEmailer.send({
          to: email,
          subject: "Sign in to MyApp",
          html: renderSignInEmail({ url, otp, challenge }),
        });
      },
    }),
  ],
});
```

```ts
// lib/auth-client.ts
import { createAuthClient } from "better-auth/client";
import { emailChallengeClient } from "better-auth-email-challenge/client";

export const authClient = createAuthClient({
  plugins: [emailChallengeClient()],
});
```

Run the schema migration:

```bash
npx @better-auth/cli generate
npx @better-auth/cli migrate
```

That's it — the plugin works out of the box with the built-in HTML confirmation page. Read on to host the page in your own app or to switch link modes.

## Driving the flow from your UI

The two completion paths require slightly different UI plumbing. They're independent — you can ship one, the other, or both.

### Path A: user types the OTP from the email

A plain `<input>` next to the "Check your email" message:

```ts
const result = await authClient.emailChallenge.verifyOtp({ otp });
if (result.data) {
  // The session cookie is already set in the response. The user IS signed
  // in. No polling needed for this path — verify-otp is the complete flow.
  window.location.href = "/dashboard";
} else {
  // result.error.code: "INVALID_OTP" | "TOO_MANY_ATTEMPTS" | "INVALID_CHALLENGE"
  showError(result.error);
}
```

### Path B: the user clicks the link in their email

Poll until something happens on the server (the user opens the email, clicks the link, confirms — possibly on another device):

```ts
await authClient.signIn.emailChallenge({
  email,
  // callbackURL is only used by linkMode: "magic-link"; the polling-tab
  // flow below decides where to navigate after the session lands.
});

const tick = setInterval(async () => {
  const { data } = await authClient.emailChallenge.poll();
  if (data?.status === "completed") {
    clearInterval(tick);
    window.location.href = "/dashboard"; // session cookie is set
  } else if (data?.status === "expired") {
    clearInterval(tick);
    // Show "challenge expired" UI; offer to retry.
  }
}, 2000);
```

A production-grade polling loop should back off (1s → 2s → 5s) and pause when `document.hidden`. The endpoint is rate-limited at `10s / 20 requests`, so casual polling is fine.

### Putting it together

Most apps want both: a "Check your email" screen with an OTP input that's _also_ polling for a link click. Both paths terminate in the same place — a signed-in session, a `window.location.href = "/dashboard"`. Whichever one fires first wins; the other ends up looking at a consumed challenge and returns `expired` (poll) or `CHALLENGE_ALREADY_CONSUMED` (verify-otp). That's expected.

## Auth paths

A user can complete an email challenge two ways:

1. **OTP code (same-device)** — they type the 6-digit code from the email into the original browser. Plain same-device fallback. Always available.
2. **Click the email link** — what happens depends on _which browser_ opens the email.

For the link path, there are two distinct flows. Knowing which one applies determines what the consumer's approval page should render.

### Same-device click

The user opens the email on the _same_ browser they used to start signing in. The signed `email_challenge` cookie is sent with the click. The plugin advances the challenge to `approved` automatically — the cookie binding is the user's affirmation (no third party can possess this user's cookie).

The user sees a _"Sign-in approved — return to your other tab"_ page (or your consumer-hosted equivalent with `state: "approved"`), and the original tab's poll completes with a session.

### Cross-device click

The user opens the email on a _different_ browser. The challenge cookie is **not** sent. The plugin shows a confirmation page with the contextual approval info (_"Sign-in from Chrome on macOS"_) plus a single **Confirm sign-in** button. That POST advances the challenge to `approved`, and the original cookie-holding browser's poll mints the session.

This extra step is what makes the cross-device path safe against two attacks:

- **Mail-scanner prefetch.** Mimecast / SafeLinks / Proofpoint GET every link to scan for malware. They don't submit forms. If GET alone advanced the challenge, an attacker who initiated a flow with the victim's email would have their poll complete the moment the gateway scanned the email — granting them a session as the victim. The GET-renders / POST-mutates split blocks this.
- **Link phishing.** The contextual approval screen gives the user a chance to notice the request didn't originate from them and bail.

### State summary

| User opens email on…          | State the consumer's page sees | Recommended UI                                |
| ----------------------------- | ------------------------------ | --------------------------------------------- |
| Original browser              | `"approved"`                   | "Sign-in approved — return to your other tab" |
| Different browser             | `"needs-confirmation"`         | Contextual approval screen + Confirm form     |
| Token is expired/used/unknown | `"invalid"`                    | Generic "link no longer valid"                |

(In `linkMode: "same-device"` or `"magic-link"`, the "different browser" row becomes `"wrong-browser"` instead. See below.)

## `linkMode` — three named tradeoffs

The `linkMode` option controls only the email **link** click flow. The OTP path is unaffected by it.

```ts
emailChallenge({
  sendChallengeEmail,
  linkMode: "cross-device", // default — supports both same- and cross-device
  // linkMode: "same-device", // reject cross-device clicks; polling tab signs in
  // linkMode: "magic-link",  // reject cross-device clicks; click tab signs in
});
```

| `linkMode`                 | Cross-device click                          | Same-device click                                   | Signed-in tab          |
| -------------------------- | ------------------------------------------- | --------------------------------------------------- | ---------------------- |
| `"cross-device"` (default) | Confirm page → POST → polling tab completes | CAS to `approved` → polling tab completes           | Original (polling) tab |
| `"same-device"`            | Wrong-browser error                         | CAS to `approved` → polling tab completes           | Original (polling) tab |
| `"magic-link"`             | Wrong-browser error                         | Click response mints session + 302 to `callbackURL` | Click tab              |

Pick `"same-device"` if you want polling-tab UX but want to reject cross-device clicks (no contextual approval page surface). Pick `"magic-link"` for the classic UX where the user lands on the destination in whichever tab opened the email.

`POST /email-challenge/verify` is only enabled in `"cross-device"` mode — the same-device-only modes have no separate confirmation step, so the POST returns `CROSS_DEVICE_DISABLED`.

**`callbackURL` is only consumed in `"magic-link"` mode**, where it's the 302 target after the click signs the user in. In `"cross-device"` and `"same-device"` modes the polling tab is the one that completes the flow, so your client decides where to navigate after `poll()` returns `completed`. Passing `callbackURL` in those modes is harmless — it's just ignored. It's still validated against `trustedOrigins` at start-time to prevent rewrite phishing.

## Wanting only the link, or only the OTP

The plugin provides both primitives in every mode — you compose the UX:

- **Link only.** Don't include the OTP in the email and don't build a verify-otp UI. The `verify-otp` endpoint stays available (rate-limited, hashed-at-rest), but is unreachable from your users.
- **OTP only.** Don't include the URL in the email and don't build a confirm page on the consumer side. The `verify` endpoint stays available but no link points at it.
- **Both** (default). Include both in the email; users pick whichever is more convenient.

No "disable OTP" or "disable link" option is needed — these are UI choices, not plugin configuration.

## Custom approval page (consumer-hosted)

By default `GET /api/auth/email-challenge/verify` renders a built-in HTML confirmation page. For any non-trivial product you'll want to host that page in your own app for design / language / brand consistency. Set `approvalPageURL` and the plugin 302s to your page instead:

```ts
emailChallenge({
  sendChallengeEmail,
  approvalPageURL: "/auth/confirm-signin",
});
```

The redirect is `${approvalPageURL}?token=<...>`. Your page reads `token`, calls the **context endpoint** as the single source of truth, and renders accordingly:

```ts
type ContextResponse =
  | { state: "invalid" }
  | {
      state: "needs-confirmation" | "approved";
      email: string;
      ipAddress: string | null;
      userAgent: string | null;
      expiresAt: Date;
      postURL: string;
    }
  | {
      // Only in linkMode: "same-device" | "magic-link":
      state: "wrong-browser";
      email: string;
      ipAddress: string | null;
      userAgent: string | null;
      expiresAt: Date;
    };
```

### SSR page (Next.js App Router)

Server components call the plugin's API **in-process** — same auth instance, no HTTP round-trip:

```tsx
// app/auth/confirm-signin/page.tsx
import { auth } from "@/lib/auth";
import { headers } from "next/headers";

export default async function ConfirmSignIn({ searchParams }) {
  const { token } = await searchParams;
  const ctx = await auth.api.getEmailChallengeContext({
    query: { token },
    headers: await headers(), // needed if you use linkMode: "same-device" | "magic-link"
  });

  if (ctx.state === "invalid")
    return <p>This sign-in link is no longer valid.</p>;
  if (ctx.state === "approved")
    return <p>Sign-in approved. You can close this tab.</p>;
  if (ctx.state === "wrong-browser")
    return <p>Open this link in the browser you started signing in on.</p>;

  // ctx.state === "needs-confirmation"
  return (
    <main>
      <h1>Sign in to MyApp</h1>
      <dl>
        <dt>Account</dt>
        <dd>{ctx.email}</dd>
        <dt>From</dt>
        <dd>{ctx.userAgent}</dd>
        <dt>IP</dt>
        <dd>{ctx.ipAddress}</dd>
      </dl>
      <form method="POST" action={ctx.postURL}>
        <input type="hidden" name="token" value={token} />
        <button type="submit">Confirm sign-in</button>
      </form>
    </main>
  );
}
```

Same shape works in Astro frontmatter, Remix `loader`, SvelteKit `+page.server.ts`, Hono, etc.

### SPA page (no SSR)

```tsx
// /auth/confirm-signin route
import { authClient } from "@/lib/auth-client";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

export default function ConfirmSignIn() {
  const [params] = useSearchParams();
  const token = params.get("token")!;
  const [ctx, setCtx] = useState<any>(null);

  useEffect(() => {
    authClient.emailChallenge
      .context({ query: { token } })
      .then((r) => setCtx(r.data));
  }, [token]);

  if (!ctx) return <p>Loading…</p>;
  if (ctx.state === "invalid")
    return <p>This sign-in link is no longer valid.</p>;
  if (ctx.state === "approved")
    return <p>Sign-in approved. You can close this tab.</p>;
  if (ctx.state === "wrong-browser")
    return <p>Open this link in the browser you started signing in on.</p>;

  return (
    <main>
      <h1>Sign in to MyApp</h1>
      <p>
        Sign-in from {ctx.userAgent} ({ctx.ipAddress})?
      </p>
      <form method="POST" action={ctx.postURL}>
        <input type="hidden" name="token" value={token} />
        <button type="submit">Confirm sign-in</button>
      </form>
    </main>
  );
}
```

The form `POST`s directly to the plugin via a plain HTML form — **no JS required to submit.** Works under strict CSP, with JS disabled, in older browsers.

### Inline HTML override

If you don't want to host a page but want to customize the plugin's built-in HTML (e.g., for a quick rebrand without a separate route), use `renderApprovalPage` instead of `approvalPageURL`:

```ts
emailChallenge({
  sendChallengeEmail,
  renderApprovalPage: ({ state, token, postURL, challenge }) => {
    // Return a full HTML string. The plugin sets cache-control: no-store
    // and X-Robots-Tag: noindex,nofollow on the response automatically.
    return `<!doctype html>...`;
  },
});
```

The callback is invoked for every state (`needs-confirmation`, `approved`, `invalid`, plus `wrong-browser` in same-device-only modes). If both options are set, `approvalPageURL` wins.

## Options reference

```ts
emailChallenge({
  // Required.
  sendChallengeEmail,

  // Defaults shown.
  expiresIn: 300, // seconds. Matches magic-link.
  maxAttempts: 3, // OTP attempts before lockout. Matches email-otp.
  otpLength: 6, // OTP digit count.
  disableSignUp: false, // if true, unknown emails are rejected at completion.
  retainConsumedChallenges: false, // keep rows after consumption for audit.
  linkMode: "cross-device", // also: "same-device" | "magic-link"
  rateLimit: { window: 60, max: 3 }, // for start / verify-otp / verify (POST).
  cookieName: "email_challenge", // override if the default collides with another plugin.

  // Optional — customizing the approval page.
  approvalPageURL: undefined, // 302 to your page (see above).
  renderApprovalPage: undefined, // or return your own HTML inline.
});
```

## Schema

This plugin adds one table:

```ts
emailChallenge {
  id                   string  (pk)
  email                string
  hashedApprovalToken  string  (sha-256 of the approval token)
  hashedOtp            string  (sha-256 of the OTP)
  browserBindingHash   string  (sha-256 of the browser secret stored in the cookie)
  status               string  // pending | approved | consuming | consumed | expired | canceled
  attempts             number
  name                 string?
  callbackURL          string?
  ipAddress            string?
  userAgent            string?
  expiresAt            date
  approvedAt           date?
  consumedAt           date?
  createdAt            date
  updatedAt            date
}
```

`consuming` is a transient state the plugin enters during the atomic `approved → consumed` CAS. All three secrets (approval token, OTP, browser binding) are SHA-256 hashed at rest — cleartext only ever exists in the email and in the browser's signed cookie.

## Security model

Three invariants:

1. **Browser-bound completion.** `verify-otp` and `poll` both require the signed `email_challenge` cookie. The session is always issued to the browser that initiated the flow — not the one that opened the email.
2. **Approval is a state flip, not a session mint.** Clicking the email link cannot — under any conditions — issue a session in `linkMode: "cross-device"` or `"same-device"`. The cookie-bound poll is the only path. (`linkMode: "magic-link"` is the explicit opt-in to classic UX where the click _does_ mint a session.)
3. **GET-renders / POST-mutates.** The cross-device path's GET endpoint is inert; only an explicit POST flips state. Same-device clicks are exempt only because the cookie binding _is_ the user's affirmation.

### Defenses in place

- **Mail-scanner prefetch hijack.** GET-renders / POST-mutates split blocks scanners that follow links but don't submit forms.
- **Atomic consume.** State transitions are CAS — two parallel polls cannot both mint sessions from one approval.
- **OTP brute force.** Default `maxAttempts: 3`. The attempt counter is incremented with a CAS predicate so two parallel wrong guesses can't both succeed past the cap.
- **`callbackURL` rewrite phishing.** Validated against `betterAuth({ trustedOrigins })` at start time, stored in the challenge row, never re-read from the URL/body during approval.
- **Approval error enumeration.** Every invalid-token case returns the same `INVALID_TOKEN`. The `retainConsumedChallenges` option doesn't change observable responses.
- **Repeat-click idempotency.** POSTing the same valid token twice is a success on both calls.
- **Cookie parsing.** The challenge cookie's secret half is validated against `/^[A-Za-z0-9]{32}$/` so the separator can't be a parse oracle.
- **Constant-time comparison** on OTP and browser-binding hashes.
- **HMAC-signed cookies** via `ctx.context.secret`; `httpOnly`, `secure` (in production), `sameSite: "lax"`, `path: "/"`.
- **Trusted origins.** The plugin reuses your `betterAuth({ trustedOrigins })` list via `originCheck`; it doesn't declare its own.
- **Rate limits.** `60s/3` for start / verify-otp / verify (POST). Polling and context-fetch are on a separate lenient `10s/20`.

### Defaults

| Option                     | Default             | Why                                                                           |
| -------------------------- | ------------------- | ----------------------------------------------------------------------------- |
| `expiresIn`                | `300` (5 min)       | Matches `magic-link`. Tighter = smaller intercept window.                     |
| `maxAttempts`              | `3`                 | Matches `email-otp`.                                                          |
| `otpLength`                | `6`                 | Same as `email-otp`.                                                          |
| `retainConsumedChallenges` | `false`             | Delete-on-consumption, same as `device-authorization`.                        |
| `linkMode`                 | `"cross-device"`    | Full feature set. The two same-device-only modes are opt-in.                  |
| `cookieName`               | `"email_challenge"` | Browser-bound challenge cookie name (Better Auth's prefix is applied on top). |

## Comparison to related plugins

| Concern                           | `magic-link`   | `email-otp`        | `email-challenge`                                 |
| --------------------------------- | -------------- | ------------------ | ------------------------------------------------- |
| Single email with both link + OTP | No             | No                 | **Yes**                                           |
| Safe cross-device sign-in         | No             | Yes                | **Yes**                                           |
| One challenge per attempt         | No             | No                 | **Yes**                                           |
| Approval click mints a session    | Yes            | N/A                | **No** (default) / Yes (`linkMode: "magic-link"`) |
| Browser-bound completion          | No             | No                 | **Yes**                                           |
| Hashed tokens at rest             | Yes            | No (plaintext OTP) | **Yes**                                           |
| Constant-time OTP compare         | N/A            | No (`===`)         | **Yes**                                           |
| Status-rich audit row             | No             | No                 | **Yes**                                           |
| Atomic consume CAS                | N/A (one-shot) | No                 | **Yes**                                           |

## FAQ / Troubleshooting

**The user clicks the link but never gets signed in.**
Most likely the polling tab is closed. In default `linkMode: "cross-device"` mode, the session is always minted by the originating browser's poll — if the user closed that tab, they need to start over. To support "click anywhere, sign in there," switch to `linkMode: "magic-link"`.

**The polling tab gets `"expired"` immediately after a successful click.**
That's the magic-link-style flow at work (`linkMode: "magic-link"`) — the click tab is the signed-in tab, and the polling tab's challenge cookie was cleared. Check `authClient.getSession()` from the polling tab to detect that the user is signed in elsewhere.

**Users are getting "wrong browser" errors when they really did open the email on the same device.**
Likely a cookie-domain mismatch. The challenge cookie is host-only by default. If your sign-in form and your `approvalPageURL` are on different subdomains, enable `betterAuth({ advanced: { crossSubDomainCookies: { enabled: true, domain: "example.com" } } })`.

**The email scanner at our corp inbox is pre-fetching the link. Is the user's auth advancing without them clicking Confirm?**
No. The GET endpoint is inert (renders HTML, no state change). Only the explicit Confirm-button POST advances state. This is tested.

**I want to ship a single-language English app and skip the consumer-hosted page entirely.**
You don't have to do anything — the built-in HTML page works out of the box. If you want to rebrand without a separate route, use `renderApprovalPage` to return your own HTML string.

**Can the user click the link from email opened in their browser's own preview pane (e.g., Gmail Web)?**
Yes. That's a same-device click — the user is in the same browser. They'll see the "Sign-in approved" page and the original tab's poll will complete.

**The `same-device shortcut` works on a freshly-opened private window?**
No — private windows don't share cookies with the parent profile, so the challenge cookie isn't sent. From the plugin's perspective it's a cross-device click. This is correct: the private window is, by design, a separate identity.

## Limitations / roadmap

- **SSE / WebSocket completion.** v1 uses short polling; SSE is additive and could land later without breaking the API.
- **Approximate-location display** in the approval email. Would require an IP→geo dependency, intentionally not bundled.
- **Pluggable token / OTP generators** beyond the built-in random ones.

## Development

```bash
pnpm install
pnpm typecheck
pnpm test
pnpm build
```

### Version compatibility matrix

CI runs the suite against both ends of the supported `better-auth` range:

```bash
pnpm run test:matrix          # 1.5.0 (floor) and latest
MATRIX_VERSIONS=1.5.0,1.5.6,latest pnpm run test:matrix
```

The matrix runs on every push and PR via `.github/workflows/ci.yml`. If a new `better-auth` release breaks the floor, the matrix catches it.

## License

MIT — see [LICENSE](./LICENSE).
