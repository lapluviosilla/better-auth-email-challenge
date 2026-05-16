import type { BetterAuthPlugin } from "better-auth";

import { EMAIL_CHALLENGE_ERROR_CODES } from "./errors";
import { getEmailChallengeContext } from "./routes/context";
import { pollEmailChallenge } from "./routes/poll";
import { startEmailChallenge } from "./routes/start";
import {
  verifyEmailChallengeGet,
  verifyEmailChallengePost,
} from "./routes/verify";
import { verifyEmailChallengeOtp } from "./routes/verify-otp";
import { schema } from "./schema";
import type { EmailChallengeOptions } from "./types";

const DEFAULTS = {
  // 5 minutes — matches magic-link. Long enough for the cross-device hop,
  // short enough to keep the replay/intercept surface small.
  expiresIn: 60 * 5,
  // 3 — matches email-otp's default. With a 6-digit OTP, 3 attempts caps
  // brute force at 3 × (1 / 10^6) probability per challenge.
  maxAttempts: 3,
  otpLength: 6,
  disableSignUp: false,
  retainConsumedChallenges: false,
  linkMode: "cross-device",
  cookieName: "email_challenge",
} as const;

export const emailChallenge = (options: EmailChallengeOptions) => {
  const opts = {
    ...DEFAULTS,
    ...options,
  };

  return {
    id: "email-challenge",
    schema,
    endpoints: {
      signInEmailChallenge: startEmailChallenge(opts),
      // GET = render page (or redirect to consumer page) + same-device shortcut.
      // POST = the actual state transition. Same path, two verbs, matching
      // magic-link's `/magic-link/verify` URL signature.
      emailChallengeVerifyPage: verifyEmailChallengeGet(opts),
      emailChallengeVerify: verifyEmailChallengePost(opts),
      verifyEmailChallengeOtp: verifyEmailChallengeOtp(opts),
      pollEmailChallenge: pollEmailChallenge(opts),
      getEmailChallengeContext: getEmailChallengeContext(opts),
    },
    rateLimit: [
      // Tight limit on the verbs an attacker can spam: start (email send +
      // DB write), verify-otp (brute-force vector), and verify POST.
      {
        pathMatcher(path) {
          return (
            path === "/sign-in/email-challenge" ||
            path === "/email-challenge/verify-otp" ||
            path === "/email-challenge/verify"
          );
        },
        window: opts.rateLimit?.window ?? 60,
        max: opts.rateLimit?.max ?? 3,
      },
      // Polling and context-fetch are high-frequency from legit clients —
      // a strict 3/60s would block real users in seconds. Allow generous
      // polling while still capping pathological traffic.
      {
        pathMatcher(path) {
          return (
            path === "/email-challenge/poll" ||
            path === "/email-challenge/context"
          );
        },
        window: 10,
        max: 20,
      },
    ],
    $ERROR_CODES: EMAIL_CHALLENGE_ERROR_CODES,
    options,
  } satisfies BetterAuthPlugin;
};
