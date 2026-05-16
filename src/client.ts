import type { BetterAuthClientPlugin } from "better-auth";

import { EMAIL_CHALLENGE_ERROR_CODES } from "./errors";
import type { emailChallenge } from "./plugin";

export const emailChallengeClient = () =>
  ({
    id: "email-challenge",
    $InferServerPlugin: {} as ReturnType<typeof emailChallenge>,
    atomListeners: [
      {
        matcher: (path: string) =>
          path === "/email-challenge/verify-otp" ||
          path === "/email-challenge/poll",
        signal: "$sessionSignal",
      },
    ],
    $ERROR_CODES: EMAIL_CHALLENGE_ERROR_CODES,
  }) satisfies BetterAuthClientPlugin;
