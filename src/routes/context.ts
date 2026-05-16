import { createAuthEndpoint } from "better-auth/api";
import * as z from "zod";

import { readChallengeCookie } from "../cookies";
import { constantTimeEqualHex, sha256Hex } from "../crypto";
import { EMAIL_CHALLENGE_MODEL, type EmailChallengeRecord } from "../schema";
import type { EmailChallengeOptions } from "../types";
import { computeVerifyPostURL, isExpired } from "./shared";

const querySchema = z.object({ token: z.string() });

/**
 * Single source of truth for consumer-hosted approval pages. Returns
 * everything the page needs to render the right UI for a given token:
 *
 *   `{ state: "invalid" }`
 *     Token is unknown, expired, consumed, canceled, or any other terminal
 *     state. Render "this link is no longer valid".
 *
 *   `{ state: "needs-confirmation", email, ipAddress, userAgent, expiresAt, postURL }`
 *     Cross-device click waiting for explicit confirmation. Render the
 *     contextual approval screen + a `<form method="POST" action={postURL}>`
 *     with a hidden `token` field and a Confirm button.
 *     (Only returned when `linkMode: "cross-device"`.)
 *
 *   `{ state: "approved", email, ipAddress, userAgent, expiresAt, postURL }`
 *     Same-device shortcut already advanced the state in the preceding GET
 *     (or someone POSTed `/email-challenge/verify` with the token).
 *     Render "Sign-in approved. Return to your other tab." No form needed.
 *
 *   `{ state: "wrong-browser", email, ipAddress, userAgent, expiresAt }`
 *     Plugin is in `linkMode: "same-device"` or `linkMode: "magic-link"`
 *     and the request came from a browser that doesn't hold the matching
 *     challenge cookie. Render an error directing the user back to the
 *     original browser or to use the OTP from the email. No `postURL`
 *     because there's no Confirm form in those modes.
 *
 * SSR consumers call this in-process via
 * `auth.api.getEmailChallengeContext({ query: { token }, headers })`.
 * SPA consumers call it over HTTP via
 * `authClient.emailChallenge.context({ query: { token } })` — the browser
 * automatically sends the cookie on the same-origin fetch.
 *
 * Note: in the same-device-only modes this endpoint *reads* the request's
 * challenge cookie to decide between `wrong-browser` and the live states.
 * SSR consumers must therefore forward the request headers — most
 * frameworks have a one-liner for this (Next.js: `await headers()`,
 * Astro: `Astro.request.headers`, etc.).
 */
export const getEmailChallengeContext = (
  opts: Pick<EmailChallengeOptions, "linkMode"> &
    Required<Pick<EmailChallengeOptions, "cookieName">>,
) =>
  createAuthEndpoint(
    "/email-challenge/context",
    {
      method: "GET",
      query: querySchema,
      metadata: {
        openapi: {
          description:
            "Fetch the approval state and context for an email-challenge token. Returns { state: 'invalid' } for any terminal/unknown token, { state: 'needs-confirmation'|'approved', email, ipAddress, userAgent, expiresAt, postURL } for live challenges in cross-device mode, or { state: 'wrong-browser', email, ipAddress, userAgent, expiresAt } in same-device-only modes when the request browser doesn't match.",
        },
      },
    },
    async (ctx) => {
      const hashed = await sha256Hex(ctx.query.token);
      const record = await ctx.context.adapter.findOne<EmailChallengeRecord>({
        model: EMAIL_CHALLENGE_MODEL,
        where: [{ field: "hashedApprovalToken", value: hashed }],
      });

      if (
        !record ||
        isExpired(record) ||
        (record.status !== "pending" && record.status !== "approved")
      ) {
        return ctx.json({ state: "invalid" as const });
      }

      // In same-device-only modes, surface wrong-browser as a distinct
      // state so the consumer can render the right message instead of a
      // generic "invalid". In cross-device mode this never fires — the
      // cross-device click is the legitimate `needs-confirmation` path.
      const mode = opts.linkMode ?? "cross-device";
      if (mode === "same-device" || mode === "magic-link") {
        const cookie = await readChallengeCookie(ctx, opts.cookieName);
        let isSameDevice = false;
        if (cookie && cookie.challengeId === record.id) {
          const expected = await sha256Hex(cookie.browserSecret);
          isSameDevice = constantTimeEqualHex(
            expected,
            record.browserBindingHash,
          );
        }
        if (!isSameDevice) {
          return ctx.json({
            state: "wrong-browser" as const,
            email: record.email,
            ipAddress: record.ipAddress ?? null,
            userAgent: record.userAgent ?? null,
            expiresAt: new Date(record.expiresAt),
          });
        }
      }

      // Map the internal DB status to the consumer-facing API state. Internal
      // `pending` is what device-auth-style state machines call the waiting
      // state; externally we name it after the UI action the consumer needs
      // to render ("show a Confirm button").
      return ctx.json({
        state:
          record.status === "pending"
            ? ("needs-confirmation" as const)
            : ("approved" as const),
        email: record.email,
        ipAddress: record.ipAddress ?? null,
        userAgent: record.userAgent ?? null,
        expiresAt: new Date(record.expiresAt),
        postURL: computeVerifyPostURL(ctx.context.baseURL),
      });
    },
  );
