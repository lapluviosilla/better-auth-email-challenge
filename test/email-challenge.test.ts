import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAuthClient } from "better-auth/client";
import { getTestInstance } from "better-auth/test";

import { emailChallenge } from "../src";
import { emailChallengeClient } from "../src/client";
import type { ChallengeEmailPayload } from "../src/types";

const NEW_EMAIL = "new-user@example.com";

const buildHarness = async (
  overrides: Partial<Parameters<typeof emailChallenge>[0]> = {},
) => {
  let lastEmail: ChallengeEmailPayload | null = null;
  const sendChallengeEmail = vi.fn(async (payload: ChallengeEmailPayload) => {
    lastEmail = payload;
  });

  const { customFetchImpl, testUser, cookieSetter, db } = await getTestInstance(
    {
      plugins: [
        emailChallenge({
          sendChallengeEmail,
          ...overrides,
        }),
      ],
    },
  );

  const client = createAuthClient({
    plugins: [emailChallengeClient()],
    fetchOptions: { customFetchImpl },
    baseURL: "http://localhost:3000",
    basePath: "/api/auth",
  });

  const fetchAuth = async (
    path: string,
    init: RequestInit & { headers?: Headers } = {},
  ): Promise<{ res: Response; body: any; text: string }> => {
    const headers = init.headers ?? new Headers();
    if (init.body && !headers.has("content-type"))
      headers.set("content-type", "application/json");
    const res = await customFetchImpl(`http://localhost:3000/api/auth${path}`, {
      ...init,
      headers,
    });
    const text = await res.text();
    let body: any = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = text;
    }
    return { res, body, text };
  };

  const absorbCookies = (target: Headers, res: Response) => {
    cookieSetter(target)({ response: res } as any);
  };

  const tokenFromLastEmail = () => {
    const u = new URL(lastEmail!.url);
    return u.searchParams.get("token")!;
  };

  return {
    client,
    testUser,
    customFetchImpl,
    db,
    fetchAuth,
    absorbCookies,
    sendChallengeEmail,
    getLastEmail: () => lastEmail,
    tokenFromLastEmail,
  };
};

const startChallenge = async (
  h: Awaited<ReturnType<typeof buildHarness>>,
  email: string,
  headers: Headers,
  extra: Record<string, unknown> = {},
) => {
  const res = await h.fetchAuth("/sign-in/email-challenge", {
    method: "POST",
    headers,
    body: JSON.stringify({ email, ...extra }),
  });
  h.absorbCookies(headers, res.res);
  return res;
};

// === Happy paths ===

describe("email-challenge: same-device OTP flow", () => {
  afterEach(() => vi.useRealTimers());

  it("verify-otp succeeds with the right code, signs in the test user", async () => {
    const h = await buildHarness();
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders);

    const otp = h.getLastEmail()!.otp;
    expect(otp).toMatch(/^\d{6}$/);

    const verify = await h.fetchAuth("/email-challenge/verify-otp", {
      method: "POST",
      headers: browserHeaders,
      body: JSON.stringify({ otp }),
    });
    expect(verify.res.status).toBe(200);
    expect(verify.body.status).toBe("completed");
    expect(verify.body.user.email).toBe(h.testUser.email);
    expect(verify.res.headers.get("set-cookie")).toContain(
      "better-auth.session_token",
    );
  });
});

describe("email-challenge: cross-device approval + poll", () => {
  it("browser polls pending → POST approves on another device → next poll completes", async () => {
    const h = await buildHarness();
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders);

    const poll1 = await h.fetchAuth("/email-challenge/poll", {
      method: "GET",
      headers: browserHeaders,
    });
    expect(poll1.body.status).toBe("pending");

    // Approval comes from a different "device" — no challenge cookie.
    const token = h.tokenFromLastEmail();
    const approve = await h.fetchAuth("/email-challenge/verify", {
      method: "POST",
      body: JSON.stringify({ token }),
    });
    expect(approve.res.status).toBe(200);
    expect(approve.body.status).toBe("approved");

    const poll2 = await h.fetchAuth("/email-challenge/poll", {
      method: "GET",
      headers: browserHeaders,
    });
    expect(poll2.body.status).toBe("completed");
    expect(poll2.body.user.email).toBe(h.testUser.email);
    expect(poll2.res.headers.get("set-cookie")).toContain(
      "better-auth.session_token",
    );
  });
});

// === Security: scanner-prefetch defense (the GET-renders / POST-mutates split) ===

describe("email-challenge: same-device shortcut", () => {
  it("same-device GET (cookie matches) advances to approved AND original tab's poll completes", async () => {
    const h = await buildHarness();
    const browserHeaders = new Headers();
    const start = await startChallenge(h, h.testUser.email, browserHeaders);
    const challengeId = start.body.challengeId;

    // User clicks the email link IN THE SAME BROWSER (sends the cookie).
    const token = h.tokenFromLastEmail();
    const get = await h.fetchAuth(
      `/email-challenge/verify?token=${encodeURIComponent(token)}`,
      { method: "GET", headers: browserHeaders },
    );
    expect(get.res.status).toBe(200);
    expect(get.text).toContain("Sign-in approved");
    expect(get.text).toContain("return to the tab");

    // Critical: the click did NOT mint a session in this response — the
    // browser-bound completion invariant means only the polling browser
    // gets the session cookie.
    const cookieHeader = get.res.headers.get("set-cookie") ?? "";
    expect(cookieHeader).not.toContain("better-auth.session_token");

    // DB row advanced to `approved`.
    const after = await h.db.findOne({
      model: "emailChallenge",
      where: [{ field: "id", value: challengeId }],
    });
    expect((after as any).status).toBe("approved");

    // Now the original tab's poll completes (same browser, polling).
    const poll = await h.fetchAuth("/email-challenge/poll", {
      method: "GET",
      headers: browserHeaders,
    });
    expect(poll.body.status).toBe("completed");
    expect(poll.body.user.email).toBe(h.testUser.email);
    expect(poll.res.headers.get("set-cookie")).toContain(
      "better-auth.session_token",
    );
  });

  it("same-device shortcut does NOT trigger for a different browser (no cookie)", async () => {
    // Two browsers: A starts the flow, B clicks the link (e.g. user opens
    // the email on a different device). B has no cookie. Must NOT shortcut.
    const h = await buildHarness();
    const browserA = new Headers();
    const start = await startChallenge(h, h.testUser.email, browserA);
    const challengeId = start.body.challengeId;

    const browserB = new Headers();
    const token = h.tokenFromLastEmail();
    const get = await h.fetchAuth(
      `/email-challenge/verify?token=${encodeURIComponent(token)}`,
      { method: "GET", headers: browserB },
    );
    expect(get.text).toContain("Confirm sign-in");
    expect(get.text).not.toContain("Sign-in approved");

    // Row still pending — no state change.
    const after = await h.db.findOne({
      model: "emailChallenge",
      where: [{ field: "id", value: challengeId }],
    });
    expect((after as any).status).toBe("pending");
  });
});

describe("email-challenge: scanner-prefetch defense", () => {
  it("GET /email-challenge/verify renders HTML and does NOT change state", async () => {
    const h = await buildHarness();
    const browserHeaders = new Headers();
    const start = await startChallenge(h, h.testUser.email, browserHeaders);
    const challengeId = start.body.challengeId;

    const token = h.tokenFromLastEmail();
    const get = await h.fetchAuth(
      `/email-challenge/verify?token=${encodeURIComponent(token)}`,
      { method: "GET" },
    );
    expect(get.res.status).toBe(200);
    expect(get.res.headers.get("content-type")).toMatch(/text\/html/);
    expect(get.text).toContain("Confirm sign-in");
    expect(get.text).toContain('method="POST"');
    expect(get.res.headers.get("x-robots-tag")).toBe("noindex,nofollow");

    // Critical assertion: state must NOT have advanced from `pending`.
    const after = await h.db.findOne({
      model: "emailChallenge",
      where: [{ field: "id", value: challengeId }],
    });
    expect((after as any).status).toBe("pending");

    // Poll from the original browser still shows pending — scanner had no effect.
    const poll = await h.fetchAuth("/email-challenge/poll", {
      method: "GET",
      headers: browserHeaders,
    });
    expect(poll.body.status).toBe("pending");
  });

  it("attacker who initiated the flow CANNOT get a session via scanner prefetch", async () => {
    // This is the original critical bug: attacker uses victim's email, victim's
    // scanner GETs the link, attacker polls. After the fix, the scanner GET
    // doesn't flip status, so the attacker's poll keeps returning `pending`.
    const h = await buildHarness();
    const attackerCookies = new Headers();
    await startChallenge(h, h.testUser.email, attackerCookies);

    // Simulate scanner prefetch: GET with NO challenge cookie.
    const token = h.tokenFromLastEmail();
    await h.fetchAuth(
      `/email-challenge/verify?token=${encodeURIComponent(token)}`,
      { method: "GET" },
    );

    // Attacker poll: must NOT complete.
    const poll = await h.fetchAuth("/email-challenge/poll", {
      method: "GET",
      headers: attackerCookies,
    });
    expect(poll.body.status).toBe("pending");
    expect(poll.body.user).toBeUndefined();
    expect(poll.body.session).toBeUndefined();
  });
});

// === Security: brute force / lockout ===

describe("email-challenge: brute-force protection", () => {
  it("locks the challenge after maxAttempts wrong OTPs (default 3)", async () => {
    const h = await buildHarness(); // default maxAttempts = 3
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders);

    for (let i = 0; i < 3; i++) {
      const r = await h.fetchAuth("/email-challenge/verify-otp", {
        method: "POST",
        headers: browserHeaders,
        body: JSON.stringify({ otp: "000000" }),
      });
      expect(r.res.status).toBe(400);
      expect(r.body.code).toBe("INVALID_OTP");
    }

    const finalAttempt = await h.fetchAuth("/email-challenge/verify-otp", {
      method: "POST",
      headers: browserHeaders,
      body: JSON.stringify({ otp: h.getLastEmail()!.otp }),
    });
    expect(finalAttempt.res.status).toBe(429);
    expect(finalAttempt.body.code).toBe("TOO_MANY_ATTEMPTS");
  });
});

// === Security: atomic consume (no duplicate sessions from race) ===

describe("email-challenge: atomic consume", () => {
  it("two parallel polls after approval yield exactly ONE completion", async () => {
    const h = await buildHarness();
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders);

    const token = h.tokenFromLastEmail();
    await h.fetchAuth("/email-challenge/verify", {
      method: "POST",
      body: JSON.stringify({ token }),
    });

    // Fire two polls simultaneously. With the CAS, only one should complete.
    const [a, b] = await Promise.all([
      h.fetchAuth("/email-challenge/poll", {
        method: "GET",
        headers: browserHeaders,
      }),
      h.fetchAuth("/email-challenge/poll", {
        method: "GET",
        headers: browserHeaders,
      }),
    ]);

    const completed = [a, b].filter((r) => r.body.status === "completed");
    const losers = [a, b].filter((r) => r.body.status !== "completed");

    expect(completed.length).toBe(1);
    expect(losers.length).toBe(1);
    expect(["expired", "pending"]).toContain(losers[0]!.body.status);
  });

  it("two parallel verify-otp calls with the right OTP yield exactly ONE completion", async () => {
    const h = await buildHarness();
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders);

    const otp = h.getLastEmail()!.otp;
    const [a, b] = await Promise.all([
      h.fetchAuth("/email-challenge/verify-otp", {
        method: "POST",
        headers: browserHeaders,
        body: JSON.stringify({ otp }),
      }),
      h.fetchAuth("/email-challenge/verify-otp", {
        method: "POST",
        headers: browserHeaders,
        body: JSON.stringify({ otp }),
      }),
    ]);

    const ok = [a, b].filter((r) => r.res.status === 200);
    const bad = [a, b].filter((r) => r.res.status !== 200);
    expect(ok.length).toBe(1);
    expect(bad.length).toBe(1);
    expect(bad[0]!.body.code).toBe("CHALLENGE_ALREADY_CONSUMED");
  });
});

// === Security: callbackURL rewrite phishing closed ===

describe("email-challenge: callbackURL hardening", () => {
  it("untrusted callbackURL at start is rejected (FORBIDDEN)", async () => {
    const h = await buildHarness();
    const r = await h.fetchAuth("/sign-in/email-challenge", {
      method: "POST",
      headers: new Headers(),
      body: JSON.stringify({
        email: h.testUser.email,
        callbackURL: "https://evil.example.com/landing",
      }),
    });
    expect(r.res.status).toBe(403);
    expect(r.body.code).toBe("INVALID_CALLBACK_URL");
  });

  it("the email URL does NOT include callbackURL (no rewrite surface)", async () => {
    const h = await buildHarness();
    await startChallenge(h, h.testUser.email, new Headers(), {
      callbackURL: "/dashboard",
    });
    const url = new URL(h.getLastEmail()!.url);
    expect(url.searchParams.has("callbackURL")).toBe(false);
    expect(url.searchParams.has("token")).toBe(true);
  });

  it("approve POST ignores any body callbackURL (not even accepted as input)", async () => {
    const h = await buildHarness();
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders, {
      callbackURL: "/dashboard",
    });

    const token = h.tokenFromLastEmail();
    // Even sending callbackURL in the body — schema doesn't accept it.
    const approve = await h.fetchAuth("/email-challenge/verify", {
      method: "POST",
      body: JSON.stringify({
        token,
        callbackURL: "/somewhere-else", // ignored: not in body schema
      }),
    });
    expect(approve.res.status).toBe(200);
    expect(approve.body.status).toBe("approved");
  });
});

// === Security: enumeration channel via approve error differential closed ===

describe("email-challenge: uniform approve errors", () => {
  it("all invalid-token cases return the same INVALID_TOKEN error", async () => {
    const h = await buildHarness();

    // Truly invalid token
    const a = await h.fetchAuth("/email-challenge/verify", {
      method: "POST",
      body: JSON.stringify({ token: "totally-bogus-token-aaaaaaaaaaaaaaa" }),
    });
    expect(a.res.status).toBe(400);
    expect(a.body.code).toBe("INVALID_TOKEN");

    // Consumed token
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders);
    const token = h.tokenFromLastEmail();
    // Complete via OTP
    await h.fetchAuth("/email-challenge/verify-otp", {
      method: "POST",
      headers: browserHeaders,
      body: JSON.stringify({ otp: h.getLastEmail()!.otp }),
    });
    const b = await h.fetchAuth("/email-challenge/verify", {
      method: "POST",
      body: JSON.stringify({ token }),
    });
    expect(b.res.status).toBe(400);
    expect(b.body.code).toBe("INVALID_TOKEN");
  });

  // The README documents that the confirmation page works as a plain
  // <form method="POST">, which sends form-encoded, not JSON, AND navigates
  // the browser to the response. The endpoint must (a) accept the form
  // body and (b) return a 302 so the user never sees raw JSON. JS clients
  // that explicitly accept JSON still get the JSON contract.

  it("POST form-encoded + Accept: text/html → 302 to approvalPageURL with token", async () => {
    const h = await buildHarness({ approvalPageURL: "/auth/confirm" });
    const browserHeaders = new Headers();
    const start = await startChallenge(h, h.testUser.email, browserHeaders);
    const challengeId = start.body.challengeId;
    const token = h.tokenFromLastEmail();

    const formHeaders = new Headers();
    formHeaders.set("content-type", "application/x-www-form-urlencoded");
    formHeaders.set("accept", "text/html");
    const approve = await h.fetchAuth("/email-challenge/verify", {
      method: "POST",
      headers: formHeaders,
      body: new URLSearchParams({ token }).toString(),
      redirect: "manual" as any,
    });

    expect(approve.res.status).toBe(302);
    const location = new URL(approve.res.headers.get("location")!);
    expect(location.pathname).toBe("/auth/confirm");
    expect(location.searchParams.get("token")).toBe(token);

    // State did flip — the redirect happens AFTER the CAS, not instead of it.
    // (The GET-renders / POST-mutates invariant: state changes only on POST.)
    const row = await h.db.findOne({
      model: "emailChallenge",
      where: [{ field: "id", value: challengeId }],
    });
    expect((row as any).status).toBe("approved");
  });

  it("POST form-encoded + Accept: application/json → 200 JSON (JS-client override)", async () => {
    const h = await buildHarness({ approvalPageURL: "/auth/confirm" });
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders);
    const token = h.tokenFromLastEmail();

    const formHeaders = new Headers();
    formHeaders.set("content-type", "application/x-www-form-urlencoded");
    formHeaders.set("accept", "application/json");
    const approve = await h.fetchAuth("/email-challenge/verify", {
      method: "POST",
      headers: formHeaders,
      body: new URLSearchParams({ token }).toString(),
    });

    expect(approve.res.status).toBe(200);
    expect(approve.body.status).toBe("approved");
  });

  it("POST form-encoded with no Accept (curl */* default) → treat as browser, redirect", async () => {
    const h = await buildHarness({ approvalPageURL: "/auth/confirm" });
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders);
    const token = h.tokenFromLastEmail();

    const formHeaders = new Headers();
    formHeaders.set("content-type", "application/x-www-form-urlencoded");
    const approve = await h.fetchAuth("/email-challenge/verify", {
      method: "POST",
      headers: formHeaders,
      body: new URLSearchParams({ token }).toString(),
      redirect: "manual" as any,
    });

    expect(approve.res.status).toBe(302);
    expect(approve.res.headers.get("location")).toContain("/auth/confirm");
  });

  it("POST form-encoded without approvalPageURL → 200 built-in 'approved' HTML page", async () => {
    const h = await buildHarness();
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders);
    const token = h.tokenFromLastEmail();

    const formHeaders = new Headers();
    formHeaders.set("content-type", "application/x-www-form-urlencoded");
    formHeaders.set("accept", "text/html");
    const approve = await h.fetchAuth("/email-challenge/verify", {
      method: "POST",
      headers: formHeaders,
      body: new URLSearchParams({ token }).toString(),
    });

    expect(approve.res.status).toBe(200);
    expect(approve.res.headers.get("content-type")).toContain("text/html");
    expect(approve.text).toContain("Sign-in approved");
  });

  it("POST form-encoded idempotent re-post on approved still redirects (not JSON)", async () => {
    // The idempotent path goes through the same approvedResponse() helper,
    // so a re-post by a browser must also redirect — never raw JSON.
    const h = await buildHarness({ approvalPageURL: "/auth/confirm" });
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders);
    const token = h.tokenFromLastEmail();

    // First POST: JSON client, locks in the approved state.
    const first = await h.fetchAuth("/email-challenge/verify", {
      method: "POST",
      body: JSON.stringify({ token }),
    });
    expect(first.body.status).toBe("approved");

    // Second POST: browser form. Must redirect, not return JSON.
    const formHeaders = new Headers();
    formHeaders.set("content-type", "application/x-www-form-urlencoded");
    const second = await h.fetchAuth("/email-challenge/verify", {
      method: "POST",
      headers: formHeaders,
      body: new URLSearchParams({ token }).toString(),
      redirect: "manual" as any,
    });
    expect(second.res.status).toBe(302);
    expect(second.res.headers.get("location")).toContain("/auth/confirm");
  });

  it("repeated POST approve for an already-approved challenge is idempotent", async () => {
    const h = await buildHarness();
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders);
    const token = h.tokenFromLastEmail();

    const first = await h.fetchAuth("/email-challenge/verify", {
      method: "POST",
      body: JSON.stringify({ token }),
    });
    expect(first.body.status).toBe("approved");

    const second = await h.fetchAuth("/email-challenge/verify", {
      method: "POST",
      body: JSON.stringify({ token }),
    });
    // Idempotent: no error, same response.
    expect(second.res.status).toBe(200);
    expect(second.body.status).toBe("approved");
  });
});

// === Browser binding ===

describe("email-challenge: browser binding", () => {
  it("poll without the challenge cookie returns expired", async () => {
    const h = await buildHarness();
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders);

    const otherBrowser = new Headers();
    const poll = await h.fetchAuth("/email-challenge/poll", {
      method: "GET",
      headers: otherBrowser,
    });
    expect(poll.body.status).toBe("expired");
  });

  it("verify-otp without the challenge cookie returns INVALID_CHALLENGE", async () => {
    const h = await buildHarness();
    const r = await h.fetchAuth("/email-challenge/verify-otp", {
      method: "POST",
      headers: new Headers(),
      body: JSON.stringify({ otp: "123456" }),
    });
    expect(r.res.status).toBe(401);
    expect(r.body.code).toBe("INVALID_CHALLENGE");
  });
});

// === Context endpoint + approvalPageURL redirect (consumer-hosted pages) ===

describe("email-challenge: context endpoint", () => {
  it("returns the full state + context for a pending token", async () => {
    const h = await buildHarness();
    await startChallenge(h, h.testUser.email, new Headers());
    const token = h.tokenFromLastEmail();

    const r = await h.fetchAuth(
      `/email-challenge/context?token=${encodeURIComponent(token)}`,
      { method: "GET" },
    );
    expect(r.res.status).toBe(200);
    expect(r.body.state).toBe("needs-confirmation");
    expect(r.body.email).toBe(h.testUser.email);
    expect(r.body.postURL).toBe("/api/auth/email-challenge/verify");
    expect(r.body).toHaveProperty("ipAddress");
    expect(r.body).toHaveProperty("userAgent");
    expect(r.body).toHaveProperty("expiresAt");
  });

  it("returns state=approved after the challenge has been advanced (and before consumption)", async () => {
    const h = await buildHarness();
    const browserA = new Headers();
    await startChallenge(h, h.testUser.email, browserA);
    const token = h.tokenFromLastEmail();

    // Advance to approved via the cross-device POST path (no cookie).
    await h.fetchAuth("/email-challenge/verify", {
      method: "POST",
      body: JSON.stringify({ token }),
    });

    const r = await h.fetchAuth(
      `/email-challenge/context?token=${encodeURIComponent(token)}`,
      { method: "GET" },
    );
    expect(r.body.state).toBe("approved");
    expect(r.body.email).toBe(h.testUser.email);
    expect(r.body.postURL).toBe("/api/auth/email-challenge/verify");
  });

  it("returns { state: 'invalid' } uniformly for unknown / consumed / expired tokens", async () => {
    const h = await buildHarness();

    // Unknown
    const a = await h.fetchAuth(
      `/email-challenge/context?token=this-does-not-exist-aaaaaaaaaaaaaaa`,
      { method: "GET" },
    );
    expect(a.body).toEqual({ state: "invalid" });

    // Consumed (verify-otp completed it)
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders);
    const token = h.tokenFromLastEmail();
    await h.fetchAuth("/email-challenge/verify-otp", {
      method: "POST",
      headers: browserHeaders,
      body: JSON.stringify({ otp: h.getLastEmail()!.otp }),
    });
    const b = await h.fetchAuth(
      `/email-challenge/context?token=${encodeURIComponent(token)}`,
      { method: "GET" },
    );
    expect(b.body).toEqual({ state: "invalid" });
  });
});

describe("email-challenge: approvalPageURL redirect", () => {
  it("when set, GET /verify 302s to the consumer page with only ?token=X", async () => {
    const h = await buildHarness({ approvalPageURL: "/auth/confirm" });
    await startChallenge(h, h.testUser.email, new Headers());
    const token = h.tokenFromLastEmail();

    // Cross-device click — no cookie.
    const get = await h.fetchAuth(
      `/email-challenge/verify?token=${encodeURIComponent(token)}`,
      { method: "GET", redirect: "manual" as any },
    );
    expect(get.res.status).toBe(302);
    const location = new URL(get.res.headers.get("location")!);
    expect(location.pathname).toBe("/auth/confirm");
    expect(location.searchParams.get("token")).toBe(token);
    // State and postURL are NOT in the URL — the consumer page fetches them
    // via the context endpoint (single source of truth).
    expect(location.searchParams.get("state")).toBeNull();
    expect(location.searchParams.get("postURL")).toBeNull();
  });

  it("same-device click pre-advances the challenge; consumer's later context call sees state=approved", async () => {
    const h = await buildHarness({ approvalPageURL: "/auth/confirm" });
    const browserHeaders = new Headers();
    const start = await startChallenge(h, h.testUser.email, browserHeaders);
    const challengeId = start.body.challengeId;

    const token = h.tokenFromLastEmail();
    const get = await h.fetchAuth(
      `/email-challenge/verify?token=${encodeURIComponent(token)}`,
      { method: "GET", headers: browserHeaders, redirect: "manual" as any },
    );
    expect(get.res.status).toBe(302);

    // Row was advanced by the GET handler (same-device shortcut).
    const after = await h.db.findOne({
      model: "emailChallenge",
      where: [{ field: "id", value: challengeId }],
    });
    expect((after as any).status).toBe("approved");

    // Consumer's page would fetch context and see state=approved.
    const ctx = await h.fetchAuth(
      `/email-challenge/context?token=${encodeURIComponent(token)}`,
      { method: "GET" },
    );
    expect(ctx.body.state).toBe("approved");
  });

  it("invalid token still redirects — consumer learns it's invalid via context", async () => {
    const h = await buildHarness({ approvalPageURL: "/auth/confirm" });
    const get = await h.fetchAuth(
      `/email-challenge/verify?token=totally-bogus-token-aaaaaaaaaaaaaaa`,
      { method: "GET", redirect: "manual" as any },
    );
    expect(get.res.status).toBe(302);
    const location = new URL(get.res.headers.get("location")!);
    expect(location.pathname).toBe("/auth/confirm");

    // Consumer's context call returns { state: "invalid" }.
    const ctx = await h.fetchAuth(
      `/email-challenge/context?token=totally-bogus-token-aaaaaaaaaaaaaaa`,
      { method: "GET" },
    );
    expect(ctx.body).toEqual({ state: "invalid" });
  });

  it("rejects an untrusted approvalPageURL at request time", async () => {
    const h = await buildHarness({
      approvalPageURL: "https://evil.example.com/landing",
    });
    await startChallenge(h, h.testUser.email, new Headers());
    const token = h.tokenFromLastEmail();
    const get = await h.fetchAuth(
      `/email-challenge/verify?token=${encodeURIComponent(token)}`,
      { method: "GET", redirect: "manual" as any },
    );
    expect(get.res.status).toBeGreaterThanOrEqual(400);
    expect(get.res.status).toBeLessThan(500);
  });
});

// === linkMode: "magic-link" — pure same-device magic-link UX ===

describe("email-challenge: linkMode='magic-link'", () => {
  it("same-device click mints session in the click response + redirects to callbackURL", async () => {
    const h = await buildHarness({ linkMode: "magic-link" });
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders, {
      callbackURL: "/dashboard",
    });

    const token = h.tokenFromLastEmail();
    const get = await h.fetchAuth(
      `/email-challenge/verify?token=${encodeURIComponent(token)}`,
      { method: "GET", headers: browserHeaders, redirect: "manual" as any },
    );
    expect(get.res.status).toBe(302);
    expect(get.res.headers.get("location")).toContain("/dashboard");

    // Critical: the click tab IS the signed-in tab in this mode.
    expect(get.res.headers.get("set-cookie")).toContain(
      "better-auth.session_token",
    );
  });

  it("click from a different browser is rejected with the wrong-browser page", async () => {
    const h = await buildHarness({ linkMode: "magic-link" });
    const browserA = new Headers();
    const start = await startChallenge(h, h.testUser.email, browserA);
    const challengeId = start.body.challengeId;

    const browserB = new Headers();
    const token = h.tokenFromLastEmail();
    const get = await h.fetchAuth(
      `/email-challenge/verify?token=${encodeURIComponent(token)}`,
      { method: "GET", headers: browserB },
    );
    expect(get.res.status).toBe(200);
    expect(get.res.headers.get("content-type")).toMatch(/text\/html/);
    expect(get.text).toContain("Open this link in the original browser");

    // Row is still pending.
    const after = await h.db.findOne({
      model: "emailChallenge",
      where: [{ field: "id", value: challengeId }],
    });
    expect((after as any).status).toBe("pending");
  });

  it("POST /email-challenge/verify is disabled (returns CROSS_DEVICE_DISABLED)", async () => {
    const h = await buildHarness({ linkMode: "magic-link" });
    await startChallenge(h, h.testUser.email, new Headers());
    const token = h.tokenFromLastEmail();

    const post = await h.fetchAuth("/email-challenge/verify", {
      method: "POST",
      body: JSON.stringify({ token }),
    });
    expect(post.res.status).toBe(400);
    expect(post.body.code).toBe("CROSS_DEVICE_DISABLED");
  });

  it("context endpoint returns state='wrong-browser' for a non-matching browser", async () => {
    const h = await buildHarness({ linkMode: "magic-link" });
    const browserA = new Headers();
    await startChallenge(h, h.testUser.email, browserA);
    const token = h.tokenFromLastEmail();

    // Different browser (no cookie) calling context.
    const browserB = new Headers();
    const r = await h.fetchAuth(
      `/email-challenge/context?token=${encodeURIComponent(token)}`,
      { method: "GET", headers: browserB },
    );
    expect(r.body.state).toBe("wrong-browser");
    expect(r.body.email).toBe(h.testUser.email);
    expect(r.body.postURL).toBeUndefined(); // no Confirm form in this mode
  });

  it("context endpoint with the matching cookie does NOT return wrong-browser", async () => {
    // (Race-edge: in linkMode='magic-link', same-device click usually completes
    // the challenge before context is hit. But if context is called first
    // — e.g., a tab-switch race — we should not falsely tag it wrong-browser.)
    const h = await buildHarness({ linkMode: "magic-link" });
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders);
    const token = h.tokenFromLastEmail();

    const r = await h.fetchAuth(
      `/email-challenge/context?token=${encodeURIComponent(token)}`,
      { method: "GET", headers: browserHeaders },
    );
    expect(r.body.state).not.toBe("wrong-browser");
  });

  it("approvalPageURL redirect on wrong-browser carries token (consumer reads state via context)", async () => {
    const h = await buildHarness({
      linkMode: "magic-link",
      approvalPageURL: "/auth/confirm",
    });
    await startChallenge(h, h.testUser.email, new Headers());
    const token = h.tokenFromLastEmail();

    // Wrong-browser click (no cookie).
    const get = await h.fetchAuth(
      `/email-challenge/verify?token=${encodeURIComponent(token)}`,
      { method: "GET", redirect: "manual" as any },
    );
    expect(get.res.status).toBe(302);
    const location = new URL(get.res.headers.get("location")!);
    expect(location.pathname).toBe("/auth/confirm");
    expect(location.searchParams.get("token")).toBe(token);

    // The consumer's page would then call context (no cookie) and learn:
    const ctx = await h.fetchAuth(
      `/email-challenge/context?token=${encodeURIComponent(token)}`,
      { method: "GET" },
    );
    expect(ctx.body.state).toBe("wrong-browser");
  });

  it("renderApprovalPage is called with state='wrong-browser' in this mode", async () => {
    let lastState: string | null = null;
    const h = await buildHarness({
      linkMode: "magic-link",
      renderApprovalPage: ({ state }) => {
        lastState = state;
        return `<html><body>state=${state}</body></html>`;
      },
    });
    await startChallenge(h, h.testUser.email, new Headers());
    const token = h.tokenFromLastEmail();

    const get = await h.fetchAuth(
      `/email-challenge/verify?token=${encodeURIComponent(token)}`,
      { method: "GET" }, // no cookie = wrong-browser
    );
    expect(get.text).toContain("state=wrong-browser");
    expect(lastState).toBe("wrong-browser");
  });

  it("OTP path still works in same-device-only mode", async () => {
    const h = await buildHarness({ linkMode: "magic-link" });
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders);

    const verify = await h.fetchAuth("/email-challenge/verify-otp", {
      method: "POST",
      headers: browserHeaders,
      body: JSON.stringify({ otp: h.getLastEmail()!.otp }),
    });
    expect(verify.res.status).toBe(200);
    expect(verify.body.status).toBe("completed");
  });
});

// === linkMode: "same-device" — polling-tab UX, no cross-device ===

describe("email-challenge: linkMode='same-device'", () => {
  it("same-device click advances to approved; original tab's poll completes (no session in click response)", async () => {
    const h = await buildHarness({ linkMode: "same-device" });
    const browserHeaders = new Headers();
    const start = await startChallenge(h, h.testUser.email, browserHeaders);
    const challengeId = start.body.challengeId;

    const token = h.tokenFromLastEmail();
    const get = await h.fetchAuth(
      `/email-challenge/verify?token=${encodeURIComponent(token)}`,
      { method: "GET", headers: browserHeaders },
    );
    expect(get.res.status).toBe(200);
    expect(get.text).toContain("Sign-in approved");

    // Click response did NOT mint a session — the polling browser will.
    const cookieHeader = get.res.headers.get("set-cookie") ?? "";
    expect(cookieHeader).not.toContain("better-auth.session_token");

    const after = await h.db.findOne({
      model: "emailChallenge",
      where: [{ field: "id", value: challengeId }],
    });
    expect((after as any).status).toBe("approved");

    const poll = await h.fetchAuth("/email-challenge/poll", {
      method: "GET",
      headers: browserHeaders,
    });
    expect(poll.body.status).toBe("completed");
    expect(poll.res.headers.get("set-cookie")).toContain(
      "better-auth.session_token",
    );
  });

  it("wrong-browser click renders the wrong-browser page (no state change)", async () => {
    const h = await buildHarness({ linkMode: "same-device" });
    const browserA = new Headers();
    const start = await startChallenge(h, h.testUser.email, browserA);
    const challengeId = start.body.challengeId;

    const browserB = new Headers();
    const token = h.tokenFromLastEmail();
    const get = await h.fetchAuth(
      `/email-challenge/verify?token=${encodeURIComponent(token)}`,
      { method: "GET", headers: browserB },
    );
    expect(get.text).toContain("Open this link in the original browser");

    const after = await h.db.findOne({
      model: "emailChallenge",
      where: [{ field: "id", value: challengeId }],
    });
    expect((after as any).status).toBe("pending");
  });

  it("POST /verify is disabled (CROSS_DEVICE_DISABLED)", async () => {
    const h = await buildHarness({ linkMode: "same-device" });
    await startChallenge(h, h.testUser.email, new Headers());
    const token = h.tokenFromLastEmail();
    const post = await h.fetchAuth("/email-challenge/verify", {
      method: "POST",
      body: JSON.stringify({ token }),
    });
    expect(post.res.status).toBe(400);
    expect(post.body.code).toBe("CROSS_DEVICE_DISABLED");
  });

  it("context returns wrong-browser for a non-matching browser in this mode", async () => {
    const h = await buildHarness({ linkMode: "same-device" });
    await startChallenge(h, h.testUser.email, new Headers());
    const token = h.tokenFromLastEmail();

    const r = await h.fetchAuth(
      `/email-challenge/context?token=${encodeURIComponent(token)}`,
      { method: "GET" }, // no cookie
    );
    expect(r.body.state).toBe("wrong-browser");
  });
});

// === Expiration ===

describe("email-challenge: expiration", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("verify-otp after expiresIn returns CHALLENGE_EXPIRED", async () => {
    const h = await buildHarness({ expiresIn: 60 });
    const browserHeaders = new Headers();
    await startChallenge(h, h.testUser.email, browserHeaders);

    await vi.advanceTimersByTimeAsync(61 * 1000);

    const r = await h.fetchAuth("/email-challenge/verify-otp", {
      method: "POST",
      headers: browserHeaders,
      body: JSON.stringify({ otp: h.getLastEmail()!.otp }),
    });
    expect(r.res.status).toBe(400);
    expect(r.body.code).toBe("CHALLENGE_EXPIRED");
  });
});

// === disableSignUp ===

describe("email-challenge: disableSignUp", () => {
  it("rejects new-user emails when disableSignUp=true", async () => {
    const h = await buildHarness({ disableSignUp: true });
    const browserHeaders = new Headers();
    await startChallenge(h, NEW_EMAIL, browserHeaders);

    const r = await h.fetchAuth("/email-challenge/verify-otp", {
      method: "POST",
      headers: browserHeaders,
      body: JSON.stringify({ otp: h.getLastEmail()!.otp }),
    });
    expect(r.res.status).toBe(403);
    expect(r.body.code).toBe("NEW_USER_SIGNUP_DISABLED");
  });

  it("creates a new user by default", async () => {
    const h = await buildHarness();
    const browserHeaders = new Headers();
    await startChallenge(h, NEW_EMAIL, browserHeaders, { name: "New User" });

    const r = await h.fetchAuth("/email-challenge/verify-otp", {
      method: "POST",
      headers: browserHeaders,
      body: JSON.stringify({ otp: h.getLastEmail()!.otp }),
    });
    expect(r.res.status).toBe(200);
    expect(r.body.user.email).toBe(NEW_EMAIL);
    expect(r.body.user.emailVerified).toBe(true);
  });
});

// === Consumption lifecycle ===

describe("email-challenge: consumption lifecycle", () => {
  it("deletes the challenge row by default after successful completion", async () => {
    const h = await buildHarness();
    const browserHeaders = new Headers();
    const start = await startChallenge(h, h.testUser.email, browserHeaders);
    const challengeId = start.body.challengeId;

    const verify = await h.fetchAuth("/email-challenge/verify-otp", {
      method: "POST",
      headers: browserHeaders,
      body: JSON.stringify({ otp: h.getLastEmail()!.otp }),
    });
    expect(verify.body.status).toBe("completed");

    const after = await h.db.findOne({
      model: "emailChallenge",
      where: [{ field: "id", value: challengeId }],
    });
    expect(after).toBeNull();
  });

  it("retains the row when retainConsumedChallenges=true", async () => {
    const h = await buildHarness({ retainConsumedChallenges: true });
    const browserHeaders = new Headers();
    const start = await startChallenge(h, h.testUser.email, browserHeaders);
    const challengeId = start.body.challengeId;

    const verify = await h.fetchAuth("/email-challenge/verify-otp", {
      method: "POST",
      headers: browserHeaders,
      body: JSON.stringify({ otp: h.getLastEmail()!.otp }),
    });
    expect(verify.body.status).toBe("completed");

    const after = await h.db.findOne({
      model: "emailChallenge",
      where: [{ field: "id", value: challengeId }],
    });
    expect((after as any).status).toBe("consumed");
    expect((after as any).consumedAt).toBeTruthy();
  });
});

describe("email-challenge: sendChallengeEmail failure", () => {
  it("returns FAILED_TO_SEND_EMAIL and deletes the orphan row when the sender throws", async () => {
    // Custom harness — needs to inject a throwing sender and inspect the
    // DB directly (the shared helper assumes a happy-path sender).
    const sendChallengeEmail = vi.fn(async () => {
      throw new Error("smtp boom");
    });
    const { customFetchImpl, db } = await getTestInstance({
      // Silence the expected "sendChallengeEmail failed" error so it doesn't
      // pollute the test log. The plugin still logs it in production.
      logger: { disabled: true },
      plugins: [emailChallenge({ sendChallengeEmail })],
    });

    const res = await customFetchImpl(
      "http://localhost:3000/api/auth/sign-in/email-challenge",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "smtp-fail@example.com" }),
      },
    );
    const body = await res.json();
    expect(res.status).toBe(500);
    expect(body.code).toBe("FAILED_TO_SEND_EMAIL");

    // The orphan row should have been cleaned up.
    const rows = await db.findMany({ model: "emailChallenge" });
    expect(rows).toHaveLength(0);
  });
});

describe("email-challenge: configurable cookieName", () => {
  it("uses the configured cookie name end-to-end (start → poll → verify-otp)", async () => {
    const h = await buildHarness({ cookieName: "ec_test" });
    const browserHeaders = new Headers();
    const start = await startChallenge(h, h.testUser.email, browserHeaders);
    expect(start.res.status).toBe(200);

    // The Set-Cookie header on start should mention the custom name. Better
    // Auth prefixes user-defined cookies with the project's cookie prefix
    // (defaults to "better-auth.") so we check for the suffix.
    const setCookie = start.res.headers.get("set-cookie") ?? "";
    expect(setCookie).toMatch(/ec_test/);
    expect(setCookie).not.toMatch(/email_challenge/);

    // Poll still works — proves the read side picks up the custom name too.
    const poll = await h.fetchAuth("/email-challenge/poll", {
      method: "GET",
      headers: browserHeaders,
    });
    expect(poll.body.status).toBe("pending");

    // OTP completion also resolves the custom cookie.
    const verify = await h.fetchAuth("/email-challenge/verify-otp", {
      method: "POST",
      headers: browserHeaders,
      body: JSON.stringify({ otp: h.getLastEmail()!.otp }),
    });
    expect(verify.body.status).toBe("completed");
  });
});
