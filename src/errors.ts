import { defineErrorCodes } from "better-auth";

export const EMAIL_CHALLENGE_ERROR_CODES = defineErrorCodes({
  INVALID_CHALLENGE: "No active challenge for this browser.",
  CHALLENGE_EXPIRED: "Challenge has expired.",
  CHALLENGE_ALREADY_CONSUMED: "Challenge has already been used.",
  INVALID_TOKEN: "Invalid approval token.",
  INVALID_CALLBACK_URL: "callbackURL is not a trusted origin.",
  CROSS_DEVICE_DISABLED:
    "Cross-device link verification is disabled on this plugin.",
  INVALID_OTP: "Incorrect code.",
  TOO_MANY_ATTEMPTS: "Too many incorrect attempts.",
  NEW_USER_SIGNUP_DISABLED: "Sign up is disabled for new users.",
  FAILED_TO_SEND_EMAIL: "Failed to send sign-in email.",
  FAILED_TO_CREATE_USER: "Failed to create user.",
  FAILED_TO_CREATE_SESSION: "Failed to create session.",
});

export type EmailChallengeErrorCode = keyof typeof EMAIL_CHALLENGE_ERROR_CODES;
