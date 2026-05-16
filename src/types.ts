import type { GenericEndpointContext } from "better-auth";

export interface ChallengeEmailPayload {
  email: string;
  /** Approval URL containing the approval token as a query param. */
  url: string;
  /** Plaintext OTP for the same-device fallback. */
  otp: string;
  /** Approval context. Render this in the email body so the user can verify the request looks legitimate. */
  challenge: {
    id: string;
    expiresAt: Date;
    ipAddress?: string | null;
    userAgent?: string | null;
  };
  /** Anything the integrator passed to `signIn.emailChallenge({ metadata })`. */
  metadata?: Record<string, unknown> | undefined;
}

export interface EmailChallengeOptions {
  /**
   * Required: deliver the email. Render the body however you like — the plugin
   * never imposes a template. Both the approval URL and the OTP code are passed
   * so the same email can complete either a same-device or cross-device sign-in.
   */
  sendChallengeEmail: (
    payload: ChallengeEmailPayload,
    ctx?: GenericEndpointContext | undefined,
  ) => Promise<void> | void;

  /**
   * Seconds until the challenge expires.
   * @default 300 (5 minutes)
   */
  expiresIn?: number;

  /**
   * Number of OTP attempts before the challenge is locked.
   * @default 5
   */
  maxAttempts?: number;

  /**
   * Number of digits in the generated OTP.
   * @default 6
   */
  otpLength?: number;

  /**
   * Refuse to mint a session for an email that doesn't already have a user.
   * @default false
   */
  disableSignUp?: boolean;

  /**
   * Override the rate-limit window (seconds) and request count for start /
   * verify-otp / poll. Defaults match `email-otp`.
   */
  rateLimit?: { window: number; max: number };

  /**
   * Keep challenge rows in the database after they're consumed (successful
   * completion or brute-force lockout) for audit / forensics. By default the
   * row is deleted on consumption, mirroring `device-authorization`.
   * @default false
   */
  retainConsumedChallenges?: boolean;

  /**
   * Name of the browser-bound challenge cookie. The actual cookie name on the
   * wire is prefixed by Better Auth's cookie helper (e.g.
   * `better-auth.email_challenge`). Override if you have a name collision or
   * a multi-plugin deployment.
   * @default "email_challenge"
   */
  cookieName?: string;

  /**
   * Behavior of the link click flow. Three named tradeoffs:
   *
   * - `"cross-device"` (default): full feature set. Same-device link
   *   clicks advance the challenge silently; cross-device clicks land on
   *   a confirmation page that requires an explicit Confirm. In both
   *   cases the *originating (polling) browser* is the one that gets
   *   signed in. Use this for any app where users may open email on a
   *   different device than the one they're signing in on.
   *
   * - `"same-device"`: rejects cross-device clicks with a "wrong browser"
   *   error page. Same-device clicks advance the challenge silently and
   *   the originating (polling) browser is signed in via its next poll.
   *   `POST /email-challenge/verify` is disabled. Use this when you want
   *   to restrict sign-in to the originating browser but keep the same
   *   polling-tab UX as cross-device mode.
   *
   * - `"magic-link"`: rejects cross-device clicks with a "wrong browser"
   *   error page. Same-device clicks mint a session in the click
   *   response and 302 to `callbackURL` — *the click tab is the signed-in
   *   tab*. Classic magic-link UX, no polling required.
   *   `POST /email-challenge/verify` is disabled.
   *
   * Note: this option only governs the email *link* flow. The OTP code in
   * the email is always typed into the original (cookie-holding) browser
   * and is unaffected by this setting — it works identically across all
   * link modes.
   *
   * The "Confirm sign-in" interstitial only exists in `"cross-device"`
   * mode — it's what makes the cross-device path safe against mail-
   * scanner prefetch and link-phishing. In the same-device-only modes,
   * the cookie binding is the sufficient proof of intent.
   *
   * @default "cross-device"
   */
  linkMode?: "cross-device" | "same-device" | "magic-link";

  /**
   * URL of a consumer-hosted approval page. When set,
   * `GET /email-challenge/verify` 302s to `${approvalPageURL}?token=<token>`
   * instead of rendering the built-in HTML.
   *
   * The consumer's page reads `token` from the query string, then calls
   * `auth.api.getEmailChallengeContext({ query: { token } })` (in-process,
   * for SSR) or `authClient.emailChallenge.context({ query: { token } })`
   * (over HTTP, for SPA) to learn everything it needs:
   *
   *   - `state`: `"invalid"` | `"needs-confirmation"` | `"approved"` (or
   *     `"wrong-browser"` when `linkMode` is `"same-device"` or
   *     `"magic-link"` and the request came from a browser that doesn't
   *     hold the matching challenge cookie)
   *   - `email`, `ipAddress`, `userAgent`, `expiresAt` — contextual approval data
   *   - `postURL` — the URL the form should `method="POST"` to (only on
   *     `"needs-confirmation"`)
   *
   * The same-device shortcut runs in `GET /verify` before the redirect, so
   * a same-device click arrives at the consumer's page with the challenge
   * already advanced — the consumer's context call sees `state: "approved"`.
   *
   * Validated against `betterAuth({ trustedOrigins })` at request time.
   * Accepts both absolute URLs (`https://app.example.com/auth/confirm`) and
   * relative paths (`/auth/confirm`).
   */
  approvalPageURL?: string;

  /**
   * Override the built-in HTML rendered at `GET /email-challenge/verify`.
   * Returns the HTML for the response body. Three states are passed:
   *
   * - `"needs-confirmation"` — cross-device click. The page must contain a
   *   form that `method="POST"`s to `postURL` with a `token` field; that
   *   POST is what advances the challenge to `approved`. Do NOT call any
   *   state-mutating endpoint from this page yourself — the mail-scanner
   *   prefetch defense depends on GET-renders / POST-mutates.
   *
   * - `"approved"` — the challenge has been advanced to `approved`,
   *   typically by the same-device shortcut on this GET (the requesting
   *   browser holds the matching `email_challenge` cookie). Render a
   *   "return to your original tab" message. The session will be minted
   *   by that browser's next poll.
   *
   * - `"invalid"` — token doesn't match any pending challenge (expired,
   *   already consumed, or never existed). Render a generic error page.
   */
  renderApprovalPage?: (data: {
    /**
     * State of the challenge. The `"wrong-browser"` state is only ever
     * passed when the plugin is configured with `linkMode: "same-device"`
     * or `linkMode: "magic-link"` and the GET click came from a browser
     * other than the one that started the flow. Default-mode
     * (`"cross-device"`) consumers never see it and can safely omit it
     * from their switch.
     */
    state: "needs-confirmation" | "approved" | "wrong-browser" | "invalid";
    token: string;
    postURL: string;
    challenge: {
      email: string;
      ipAddress: string | null;
      userAgent: string | null;
      expiresAt: Date;
    } | null;
  }) => string | Promise<string>;
}
