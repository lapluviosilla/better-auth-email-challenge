import type { BetterAuthClientPlugin } from "better-auth";
import type { BetterFetchOption } from "@better-fetch/fetch";

import { EMAIL_CHALLENGE_ERROR_CODES } from "./errors";
import type { emailChallenge } from "./plugin";

export const emailChallengeClient = () =>
  ({
    id: "email-challenge",
    $InferServerPlugin: {} as ReturnType<typeof emailChallenge>,
    atomListeners: [
      // verify-otp is a one-shot: onSuccess only fires on 2xx, which is exactly
      // when the session is minted. Path-only matching is correct here.
      {
        matcher: (path: string) => path === "/email-challenge/verify-otp",
        signal: "$sessionSignal",
      },
    ],
    getActions: ($fetch, $store) => ({
      emailChallenge: {
        // poll returns 200 for pending/completed/expired (the status field
        // carries the semantics — pending polls are normal, expired is a
        // uniform-error response). The auto-generated proxy fires
        // $sessionSignal on every 2xx, which would refetch /get-session on
        // every poll tick. Override here to fire only when the response
        // actually carries a freshly-minted session.
        poll: async (
          fetchOptions?: BetterFetchOption & { disableSignal?: boolean },
        ) => {
          const res = await $fetch<{
            status: "pending" | "completed" | "expired";
          }>("/email-challenge/poll", { method: "GET", ...fetchOptions });
          if (
            res.data?.status === "completed" &&
            !fetchOptions?.disableSignal
          ) {
            // Defer to match the proxy's race-avoidance (proxy.mjs:60-66).
            setTimeout(() => $store.notify("$sessionSignal"), 10);
          }
          return res;
        },
      },
    }),
    $ERROR_CODES: EMAIL_CHALLENGE_ERROR_CODES,
  }) satisfies BetterAuthClientPlugin;
