import { APIError, createAuthEndpoint, getIp } from "better-auth/api";
import * as z from "zod";

import { setChallengeCookie } from "../cookies";
import { EMAIL_CHALLENGE_ERROR_CODES as E } from "../errors";
import {
  generateApprovalToken,
  generateBrowserSecret,
  generateOtp,
  sha256Hex,
} from "../crypto";
import {
  EMAIL_CHALLENGE_MODEL,
  type ChallengeStatus,
  type EmailChallengeRecord,
} from "../schema";
import type { EmailChallengeOptions } from "../types";

const bodySchema = z.object({
  email: z.string().email(),
  name: z.string().optional(),
  callbackURL: z.string().optional(),
  metadata: z.record(z.string(), z.any()).optional(),
});

export const startEmailChallenge = (
  opts: Required<
    Pick<EmailChallengeOptions, "expiresIn" | "otpLength" | "cookieName">
  > &
    EmailChallengeOptions,
) =>
  createAuthEndpoint(
    "/sign-in/email-challenge",
    {
      method: "POST",
      body: bodySchema,
      requireHeaders: true,
      metadata: {
        openapi: {
          description:
            "Begin an email challenge. Sends an email containing both an approval link and an OTP code, sets a browser-bound challenge cookie, and returns the challenge id so the client can poll for completion.",
        },
      },
    },
    async (ctx) => {
      const { email, name, callbackURL, metadata } = ctx.body;

      // Validate callbackURL at the point of intent so the stored value is
      // trusted-by-construction. Without this, the URL could be rewritten
      // at /email-challenge/approve time to any other trusted origin —
      // closing the rewrite-to-different-trusted-callback phishing vector.
      if (callbackURL) {
        if (
          !ctx.context.isTrustedOrigin(callbackURL, {
            allowRelativePaths: true,
          })
        ) {
          throw new APIError("FORBIDDEN", {
            code: "INVALID_CALLBACK_URL",
            message: E.INVALID_CALLBACK_URL.message,
          });
        }
      }

      const approvalToken = generateApprovalToken();
      const otp = generateOtp(opts.otpLength);
      const browserSecret = generateBrowserSecret();

      const [hashedApprovalToken, hashedOtp, browserBindingHash] =
        await Promise.all([
          sha256Hex(approvalToken),
          sha256Hex(otp),
          sha256Hex(browserSecret),
        ]);

      const expiresAt = new Date(Date.now() + opts.expiresIn * 1000);
      // Use the framework helper so trust-proxy / forwarded-header rules
      // are applied uniformly instead of trusting an attacker-controlled
      // x-forwarded-for blindly.
      const ipAddress = ctx.request
        ? (getIp(ctx.request, ctx.context.options) ?? null)
        : null;
      const userAgent = ctx.request?.headers.get("user-agent") ?? null;

      const now = new Date();
      const record = await ctx.context.adapter.create<EmailChallengeRecord>({
        model: EMAIL_CHALLENGE_MODEL,
        data: {
          email,
          hashedApprovalToken,
          hashedOtp,
          browserBindingHash,
          status: "pending" satisfies ChallengeStatus,
          attempts: 0,
          name: name ?? null,
          callbackURL: callbackURL ?? null,
          ipAddress,
          userAgent,
          expiresAt,
          approvedAt: null,
          consumedAt: null,
          createdAt: now,
          updatedAt: now,
        },
      });

      await setChallengeCookie(
        ctx,
        opts.cookieName,
        record.id,
        browserSecret,
        opts.expiresIn,
      );

      const baseURL = new URL(ctx.context.baseURL);
      const basePath = baseURL.pathname.endsWith("/")
        ? baseURL.pathname.slice(0, -1)
        : baseURL.pathname;
      // NOTE: callbackURL is intentionally NOT included in the email URL. The
      // server retrieves it from the stored challenge record at approve time
      // (see routes/approve.ts), which prevents an attacker who has the token
      // from rewriting the post-approval redirect to a different (but still
      // trusted-origin-listed) destination.
      const url = new URL(`${basePath}/email-challenge/verify`, baseURL.origin);
      url.searchParams.set("token", approvalToken);

      // Wrap the integrator's sender so a thrown error doesn't orphan a row
      // in the DB. We delete the just-created challenge on failure and
      // surface a structured FAILED_TO_SEND_EMAIL — the raw error is logged
      // server-side but never returned to the client (could leak provider
      // internals like API keys in error messages).
      try {
        await opts.sendChallengeEmail(
          {
            email,
            url: url.toString(),
            otp,
            challenge: {
              id: record.id,
              expiresAt,
              ipAddress,
              userAgent,
            },
            metadata,
          },
          ctx,
        );
      } catch (err) {
        await ctx.context.adapter
          .delete({
            model: EMAIL_CHALLENGE_MODEL,
            where: [{ field: "id", value: record.id }],
          })
          .catch(() => {
            /* best-effort; the row will expire on its own */
          });
        ctx.context.logger.error("emailChallenge: sendChallengeEmail failed", {
          err,
        });
        throw new APIError("INTERNAL_SERVER_ERROR", {
          code: E.FAILED_TO_SEND_EMAIL.code,
          message: E.FAILED_TO_SEND_EMAIL.message,
        });
      }

      return ctx.json({
        challengeId: record.id,
        expiresAt,
        status: "pending" as const,
      });
    },
  );
