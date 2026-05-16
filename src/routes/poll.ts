import { createAuthEndpoint } from "better-auth/api";

import type { ChallengeStatus } from "../schema";
import type { EmailChallengeOptions } from "../types";
import {
  completeChallenge,
  findOrCreateUser,
  isExpired,
  loadChallengeForBrowser,
  updateChallengeStatus,
} from "./shared";

/**
 * Browser-bound completion endpoint. The originating browser polls until the
 * challenge transitions to `approved`, at which point this endpoint mints the
 * session and returns it.
 *
 * Closed-tab / wrong-cookie / no-cookie all return `{ status: "expired" }`
 * rather than leaking whether a challenge exists.
 *
 * Concurrent-safe: the `approved → consuming` transition inside
 * `completeChallenge` is a CAS, so two parallel polls cannot both mint a
 * session for the same challenge. The losing poll falls through to
 * `{ status: "expired" }` (uniform-error policy — we don't reveal the race).
 */
export const pollEmailChallenge = (
  opts: Required<Pick<EmailChallengeOptions, "cookieName">> &
    EmailChallengeOptions,
) =>
  createAuthEndpoint(
    "/email-challenge/poll",
    {
      method: "GET",
      requireHeaders: true,
      metadata: {
        openapi: {
          description:
            "Poll the status of the current browser's email challenge. Returns 'completed' (with user+session) once the email approval has been received and the session has been minted.",
        },
      },
    },
    async (ctx) => {
      const record = await loadChallengeForBrowser(ctx, opts.cookieName);
      if (!record) return ctx.json({ status: "expired" as const });

      if (isExpired(record)) {
        if (record.status === "pending" || record.status === "approved") {
          await updateChallengeStatus(ctx, record.id, {
            status: "expired" satisfies ChallengeStatus,
          });
        }
        return ctx.json({ status: "expired" as const });
      }

      if (record.status === "pending") {
        return ctx.json({ status: "pending" as const });
      }

      if (record.status === "approved") {
        const { user } = await findOrCreateUser(
          ctx,
          record.email,
          record.name,
          { disableSignUp: opts.disableSignUp },
        );
        const completed = await completeChallenge(
          ctx,
          record,
          user,
          opts.retainConsumedChallenges ?? false,
          opts.cookieName,
        );
        if (!completed) {
          // Lost the CAS race. Don't leak it — uniform expired response.
          return ctx.json({ status: "expired" as const });
        }
        return ctx.json({
          status: "completed" as const,
          user: completed.user,
          session: completed.session,
        });
      }

      // status === consuming | consumed | canceled | expired
      return ctx.json({ status: "expired" as const });
    },
  );
