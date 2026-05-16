import type { GenericEndpointContext } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import * as z from "zod";

import { readChallengeCookie } from "../cookies";
import { constantTimeEqualHex, sha256Hex } from "../crypto";
import { EMAIL_CHALLENGE_ERROR_CODES as E } from "../errors";
import { EMAIL_CHALLENGE_MODEL, type EmailChallengeRecord } from "../schema";
import type { EmailChallengeOptions } from "../types";
import {
  apiError,
  casStatus,
  completeChallengeFromPending,
  computeVerifyPostURL,
  findOrCreateUser,
  isExpired,
} from "./shared";
import {
  htmlResponse,
  invalidLinkHTML,
  renderAutoApprovedPage,
  renderConfirmPage,
  wrongBrowserHTML,
} from "./verify.html";

const verifyQuerySchema = z.object({ token: z.string() });
const verifyBodySchema = z.object({ token: z.string() });

const findChallengeByToken = async (
  ctx: GenericEndpointContext,
  token: string,
): Promise<EmailChallengeRecord | null> => {
  const hashed = await sha256Hex(token);
  return ctx.context.adapter.findOne<EmailChallengeRecord>({
    model: EMAIL_CHALLENGE_MODEL,
    where: [{ field: "hashedApprovalToken", value: hashed }],
  });
};

const buildRedirectURL = (
  approvalPageURL: string,
  baseURL: string,
  token: string,
): string => {
  // approvalPageURL may be absolute or path-relative.
  const url = new URL(approvalPageURL, baseURL);
  url.searchParams.set("token", token);
  return url.toString();
};

const isApprovalPageTrusted = (
  ctx: GenericEndpointContext,
  approvalPageURL: string,
): boolean =>
  ctx.context.isTrustedOrigin(approvalPageURL, { allowRelativePaths: true });

/**
 * The URL embedded in the email points here. Renders a confirmation page that
 * requires an explicit POST to flip the challenge to `approved`. Does NOT
 * mutate state on GET except via the same-device shortcut below.
 *
 * ## The same-device shortcut
 *
 * If the GET carries the matching `email_challenge` cookie, this is — by
 * cookie-binding construction — the same browser that started the flow. We
 * advance the state atomically here (CAS `pending → approved`). The session
 * is still minted by the originating browser's *next* poll; we never set a
 * session cookie on this response. That keeps the "browser-bound completion"
 * invariant intact while removing the second click for same-device users.
 *
 * Mail scanners have no user cookies. Phishers' cookies are on their own
 * browsers, not the victim's. So neither of them qualifies for the shortcut.
 *
 * ## Why GET-renders / POST-mutates (cross-device path)
 *
 * Corporate mail-security gateways (Mimecast, SafeLinks, Proofpoint, etc.)
 * GET every link to scan it. They don't submit forms. By keeping GET inert
 * (in the cross-device case), we ensure a prefetch GET can never flip an
 * attacker-initiated flow to `approved` for a session-cookie-holder elsewhere.
 */
export const verifyEmailChallengeGet = (
  opts: Pick<
    EmailChallengeOptions,
    | "renderApprovalPage"
    | "approvalPageURL"
    | "linkMode"
    | "disableSignUp"
    | "retainConsumedChallenges"
  > &
    Required<Pick<EmailChallengeOptions, "cookieName">>,
) =>
  createAuthEndpoint(
    "/email-challenge/verify",
    {
      method: "GET",
      query: verifyQuerySchema,
      metadata: {
        openapi: {
          description:
            "The URL embedded in the email. Renders a one-click confirmation page (or redirects to `approvalPageURL` if configured). Does NOT mutate state on GET unless the requesting browser holds the matching challenge cookie (same-device shortcut).",
        },
      },
    },
    async (ctx) => {
      const record = await findChallengeByToken(ctx, ctx.query.token);
      const isValid =
        !!record && record.status === "pending" && !isExpired(record);
      const postURL = computeVerifyPostURL(ctx.context.baseURL);
      const mode = opts.linkMode ?? "cross-device";

      // Detect same-device by checking whether the request carries the
      // matching `email_challenge` cookie. All three modes use this; only
      // the response to "no cookie match" differs.
      let isSameDevice = false;
      if (isValid) {
        const cookie = await readChallengeCookie(ctx, opts.cookieName);
        if (cookie && cookie.challengeId === record!.id) {
          const expected = await sha256Hex(cookie.browserSecret);
          if (constantTimeEqualHex(expected, record!.browserBindingHash)) {
            isSameDevice = true;
          }
        }
      }

      // Shared helper: render the wrong-browser / invalid path with full
      // consumer customization (approvalPageURL → redirect, then
      // renderApprovalPage, then built-in HTML). Used by both same-device-
      // only modes.
      const renderErrorState = async (
        errorState: "wrong-browser" | "invalid",
      ): Promise<Response> => {
        if (opts.approvalPageURL) {
          if (!isApprovalPageTrusted(ctx, opts.approvalPageURL)) {
            throw apiError("BAD_REQUEST", E.INVALID_CALLBACK_URL);
          }
          throw ctx.redirect(
            buildRedirectURL(
              opts.approvalPageURL,
              ctx.context.baseURL,
              ctx.query.token,
            ),
          );
        }
        if (opts.renderApprovalPage) {
          const html = await opts.renderApprovalPage({
            state: errorState,
            token: ctx.query.token,
            postURL,
            challenge:
              errorState === "wrong-browser" && record
                ? {
                    email: record.email,
                    ipAddress: record.ipAddress ?? null,
                    userAgent: record.userAgent ?? null,
                    expiresAt: new Date(record.expiresAt),
                  }
                : null,
          });
          return htmlResponse(html);
        }
        return htmlResponse(
          errorState === "wrong-browser" ? wrongBrowserHTML : invalidLinkHTML,
        );
      };

      // ─── mode: "magic-link" (classic UX, click tab signs in) ───────────
      if (mode === "magic-link") {
        if (isValid && isSameDevice) {
          const { user } = await findOrCreateUser(
            ctx,
            record!.email,
            record!.name,
            { disableSignUp: opts.disableSignUp },
          );
          const completed = await completeChallengeFromPending(
            ctx,
            record!,
            user,
            opts.retainConsumedChallenges ?? false,
            opts.cookieName,
          );
          if (completed) {
            // setSessionCookie + clearChallengeCookie already applied to
            // `ctx`. The redirect response carries those Set-Cookie headers.
            throw ctx.redirect(record!.callbackURL ?? "/");
          }
          // CAS loss is rare; fall through to error rendering below.
        }
        return renderErrorState(
          isValid && !isSameDevice ? "wrong-browser" : "invalid",
        );
      }

      // ─── mode: "same-device" (polling-tab UX, no cross-device) ─────────
      // Identical to cross-device same-device shortcut, but rejects clicks
      // from non-matching browsers instead of rendering a Confirm page.
      if (mode === "same-device") {
        if (!isValid) return renderErrorState("invalid");
        if (!isSameDevice) return renderErrorState("wrong-browser");

        const claimed = await casStatus(
          ctx,
          record!.id,
          "pending",
          "approved",
          { approvedAt: new Date() },
        );
        // Whether or not we won the CAS, the consumer's page sees the
        // post-shortcut state ("approved") via context. Render the
        // built-in "all set" page or the consumer's override.
        if (opts.approvalPageURL) {
          if (!isApprovalPageTrusted(ctx, opts.approvalPageURL)) {
            throw apiError("BAD_REQUEST", E.INVALID_CALLBACK_URL);
          }
          throw ctx.redirect(
            buildRedirectURL(
              opts.approvalPageURL,
              ctx.context.baseURL,
              ctx.query.token,
            ),
          );
        }
        if (opts.renderApprovalPage) {
          const html = await opts.renderApprovalPage({
            state: "approved",
            token: ctx.query.token,
            postURL,
            challenge: {
              email: record!.email,
              ipAddress: record!.ipAddress ?? null,
              userAgent: record!.userAgent ?? null,
              expiresAt: new Date(record!.expiresAt),
            },
          });
          return htmlResponse(html);
        }
        // claimed used as a hint only — same UX either way.
        void claimed;
        return htmlResponse(renderAutoApprovedPage());
      }

      // ─── mode: "cross-device" (default; full cross-device support) ─────
      // Same-device click → run the same-device shortcut (CAS pending →
      // approved; let the polling browser mint the session). Different
      // browser → render the confirmation page (GET-renders / POST-mutates
      // split, scanner-prefetch safe).
      //
      // External state names mirror the context endpoint's response:
      //   needs-confirmation = DB `pending`, awaiting a user click
      //   approved           = DB `approved`, ready for the polling browser
      //   invalid            = any terminal / unknown / expired state
      let state: "needs-confirmation" | "approved" | "invalid" = isValid
        ? "needs-confirmation"
        : "invalid";

      if (isSameDevice) {
        const claimed = await casStatus(
          ctx,
          record!.id,
          "pending",
          "approved",
          { approvedAt: new Date() },
        );
        if (claimed) state = "approved";
        // CAS loser falls through with state="needs-confirmation"; the
        // polling browser will find the winner's "approved" anyway.
      }

      // Consumer-hosted approval page (Option A: redirect-based). The
      // consumer's page calls `auth.api.getEmailChallengeContext` to learn
      // state (pending | approved | invalid) and render accordingly — the
      // context endpoint is the single source of truth, not query params.
      if (opts.approvalPageURL) {
        if (!isApprovalPageTrusted(ctx, opts.approvalPageURL)) {
          throw apiError("BAD_REQUEST", E.INVALID_CALLBACK_URL);
        }
        const target = buildRedirectURL(
          opts.approvalPageURL,
          ctx.context.baseURL,
          ctx.query.token,
        );
        throw ctx.redirect(target);
      }

      // Built-in HTML path.
      if (opts.renderApprovalPage) {
        const html = await opts.renderApprovalPage({
          state,
          token: ctx.query.token,
          postURL,
          challenge: isValid
            ? {
                email: record!.email,
                ipAddress: record!.ipAddress ?? null,
                userAgent: record!.userAgent ?? null,
                expiresAt: new Date(record!.expiresAt),
              }
            : null,
        });
        return htmlResponse(html);
      }

      if (state === "approved") return htmlResponse(renderAutoApprovedPage());
      if (state === "invalid") return htmlResponse(invalidLinkHTML);
      return htmlResponse(
        renderConfirmPage({
          postURL,
          token: ctx.query.token,
          email: record!.email,
          userAgent: record!.userAgent,
          ipAddress: record!.ipAddress,
          expiresAt: new Date(record!.expiresAt),
        }),
      );
    },
  );

/**
 * The state-mutating verification. Submitted by the confirmation page form,
 * or by a custom UI calling `authClient.emailChallenge.verify({ token })`.
 *
 * - Uniform `INVALID_TOKEN` for every failure case: no enumeration between
 *   never-existed / consumed / expired / wrong-status.
 * - Idempotent: a second POST on an already-`approved` challenge returns
 *   success.
 * - Does NOT mint a session — the originating browser does that via poll.
 *   That keeps the browser-bound completion invariant intact.
 *
 * Only enabled in `mode: "cross-device"`. The same-device-only modes
 * complete the flow without a POST (either via the GET shortcut or via
 * the click response itself), so this endpoint returns
 * `CROSS_DEVICE_DISABLED` in those modes.
 */
export const verifyEmailChallengePost = (
  opts: Pick<EmailChallengeOptions, "linkMode">,
) =>
  createAuthEndpoint(
    "/email-challenge/verify",
    {
      method: "POST",
      body: verifyBodySchema,
      metadata: {
        openapi: {
          description:
            "Approve a pending email challenge. The originating browser completes the session via /email-challenge/poll on its next tick. Disabled when crossDevice: false.",
        },
      },
    },
    async (ctx) => {
      if ((opts.linkMode ?? "cross-device") !== "cross-device") {
        throw apiError("BAD_REQUEST", E.CROSS_DEVICE_DISABLED);
      }

      const record = await findChallengeByToken(ctx, ctx.body.token);

      if (!record || isExpired(record)) {
        throw apiError("BAD_REQUEST", E.INVALID_TOKEN);
      }

      if (record.status === "approved") {
        return ctx.json({ status: "approved" as const });
      }

      if (record.status !== "pending") {
        throw apiError("BAD_REQUEST", E.INVALID_TOKEN);
      }

      const claimed = await casStatus(ctx, record.id, "pending", "approved", {
        approvedAt: new Date(),
      });
      if (!claimed) {
        const after = await ctx.context.adapter.findOne<EmailChallengeRecord>({
          model: EMAIL_CHALLENGE_MODEL,
          where: [{ field: "id", value: record.id }],
        });
        if (after?.status === "approved") {
          return ctx.json({ status: "approved" as const });
        }
        throw apiError("BAD_REQUEST", E.INVALID_TOKEN);
      }

      return ctx.json({ status: "approved" as const });
    },
  );
