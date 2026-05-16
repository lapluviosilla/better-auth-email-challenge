/**
 * Default HTML responses for the `/email-challenge/verify` GET handler.
 *
 * These are kept as plain template literals — no template engine, no JSX —
 * so the bundle stays tiny and the rendered output is auditable at a glance.
 * Consumers who want full control should pass `approvalPageURL` or
 * `renderApprovalPage` to the plugin; these defaults exist so the plugin is
 * usable with zero UI configuration.
 *
 * All inputs interpolated into HTML go through `htmlEscape`. Don't add a
 * new interpolation without escaping it.
 */

const htmlEscape = (s: string): string =>
  s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

export const renderConfirmPage = (args: {
  postURL: string;
  token: string;
  email: string;
  userAgent: string | null | undefined;
  ipAddress: string | null | undefined;
  expiresAt: Date;
}): string =>
  `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<meta name="robots" content="noindex,nofollow" />
<title>Confirm sign-in</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#111}
  h1{font-size:1.25rem;margin:0 0 1rem}
  dl{display:grid;grid-template-columns:max-content 1fr;gap:.25rem 1rem;font-size:.9rem;color:#444;margin:1rem 0 2rem}
  dt{font-weight:600}
  button{font:inherit;padding:.65rem 1.25rem;background:#111;color:#fff;border:0;border-radius:.5rem;cursor:pointer}
  button:hover{background:#222}
  .muted{font-size:.85rem;color:#666;margin-top:2rem}
</style>
</head><body>
<h1>Confirm sign-in</h1>
<p>You'll be signed in on the browser that requested this email. Approve only if you started this sign-in.</p>
<dl>
  <dt>Account</dt><dd>${htmlEscape(args.email)}</dd>
  ${args.userAgent ? `<dt>From</dt><dd>${htmlEscape(args.userAgent)}</dd>` : ""}
  ${args.ipAddress ? `<dt>IP</dt><dd>${htmlEscape(args.ipAddress)}</dd>` : ""}
  <dt>Expires</dt><dd>${htmlEscape(args.expiresAt.toISOString())}</dd>
</dl>
<form method="POST" action="${htmlEscape(args.postURL)}">
  <input type="hidden" name="token" value="${htmlEscape(args.token)}" />
  <button type="submit">Confirm sign-in</button>
</form>
<p class="muted">If you didn't request this, just close this window — the request will expire on its own.</p>
</body></html>`;

export const renderAutoApprovedPage = (): string => `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<meta name="robots" content="noindex,nofollow" />
<title>Sign-in approved</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#111}
  h1{font-size:1.25rem;margin:0 0 1rem}
  p{color:#444}
  .check{font-size:2rem;margin-bottom:1rem}
</style>
</head><body>
<div class="check">✓</div>
<h1>Sign-in approved</h1>
<p>You can close this window and return to the tab where you started signing in — it'll finish on its own in a moment.</p>
</body></html>`;

export const invalidLinkHTML = `<!doctype html><html><head><meta charset="utf-8"/><meta name="robots" content="noindex,nofollow"/><title>Sign-in link</title></head><body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem"><h1>This link is no longer valid</h1><p>It may have expired or already been used. Request a new sign-in to continue.</p></body></html>`;

export const wrongBrowserHTML = `<!doctype html><html><head><meta charset="utf-8"/><meta name="robots" content="noindex,nofollow"/><title>Sign-in link</title></head><body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem"><h1>Open this link in the original browser</h1><p>This sign-in link only works on the browser you started signing in from. Either click it on that browser, or enter the code from the email there.</p></body></html>`;

export const htmlResponse = (body: string, status = 200): Response =>
  new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex,nofollow",
    },
  });
