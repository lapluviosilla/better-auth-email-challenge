import { createAuthEndpoint } from "better-auth/api";
import * as z from "zod";

import { constantTimeEqualHex, sha256Hex } from "../crypto";
import { EMAIL_CHALLENGE_ERROR_CODES as E } from "../errors";
import type { ChallengeStatus } from "../schema";
import type { EmailChallengeOptions } from "../types";
import {
  apiError,
  completeChallengeFromPending,
  findOrCreateUser,
  isExpired,
  loadChallengeForBrowser,
  terminateChallenge,
  tryIncrementAttempts,
  updateChallengeStatus,
} from "./shared";

const bodySchema = z.object({
  otp: z.string().min(1),
});

export const verifyEmailChallengeOtp = (
  opts: Required<
    Pick<
      EmailChallengeOptions,
      "maxAttempts" | "retainConsumedChallenges" | "cookieName"
    >
  > &
    EmailChallengeOptions,
) =>
  createAuthEndpoint(
    "/email-challenge/verify-otp",
    {
      method: "POST",
      body: bodySchema,
      requireHeaders: true,
      metadata: {
        openapi: {
          description:
            "Same-device fallback: complete the challenge by submitting the OTP from the email. Requires the challenge cookie set during /sign-in/email-challenge.",
        },
      },
    },
    async (ctx) => {
      const record = await loadChallengeForBrowser(ctx, opts.cookieName);
      if (!record) throw apiError("UNAUTHORIZED", E.INVALID_CHALLENGE);

      if (isExpired(record)) {
        await updateChallengeStatus(ctx, record.id, {
          status: "expired" satisfies ChallengeStatus,
        });
        throw apiError("BAD_REQUEST", E.CHALLENGE_EXPIRED);
      }

      if (record.status !== "pending") {
        // approved | consuming | consumed | canceled | expired — terminal or
        // mid-claim from another path. Return the same error for all so we
        // don't leak which.
        throw apiError("BAD_REQUEST", E.CHALLENGE_ALREADY_CONSUMED);
      }

      if (record.attempts >= opts.maxAttempts) {
        await terminateChallenge(ctx, record.id, opts.retainConsumedChallenges);
        throw apiError("TOO_MANY_REQUESTS", E.TOO_MANY_ATTEMPTS);
      }

      const submitted = await sha256Hex(ctx.body.otp);
      if (!constantTimeEqualHex(submitted, record.hashedOtp)) {
        // CAS the increment so two parallel wrong-guesses can't both succeed.
        // If we lose the race, another request already moved the counter —
        // surface the same error without double-incrementing.
        await tryIncrementAttempts(ctx, record.id, record.attempts);
        throw apiError("BAD_REQUEST", E.INVALID_OTP);
      }

      const { user } = await findOrCreateUser(ctx, record.email, record.name, {
        disableSignUp: opts.disableSignUp,
      });
      const completed = await completeChallengeFromPending(
        ctx,
        record,
        user,
        opts.retainConsumedChallenges,
        opts.cookieName,
      );
      if (!completed) {
        // Lost the claim race — surface uniformly.
        throw apiError("BAD_REQUEST", E.CHALLENGE_ALREADY_CONSUMED);
      }

      return ctx.json({
        user: completed.user,
        session: completed.session,
        status: "completed" as const,
      });
    },
  );
