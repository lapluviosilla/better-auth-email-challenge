import type { GenericEndpointContext, User } from "better-auth";
import { APIError } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";

import { clearChallengeCookie, readChallengeCookie } from "../cookies";
import { constantTimeEqualHex, sha256Hex } from "../crypto";
import { EMAIL_CHALLENGE_ERROR_CODES as E } from "../errors";
import {
  EMAIL_CHALLENGE_MODEL,
  type ChallengeStatus,
  type EmailChallengeRecord,
} from "../schema";
import type { EmailChallengeOptions } from "../types";

export const apiError = (
  status: "UNAUTHORIZED" | "BAD_REQUEST" | "TOO_MANY_REQUESTS" | "FORBIDDEN",
  e: { code: string; message: string },
) => new APIError(status, { code: e.code, message: e.message });

/**
 * Build the path-only URL of the verify POST endpoint, respecting Better
 * Auth's `basePath` (which lives inside `baseURL.pathname`). Used by both
 * the built-in approval page and the context endpoint so consumers can
 * POST to the same place regardless of whether `baseURL` has a path prefix.
 */
export const computeVerifyPostURL = (baseURL: string): string => {
  const url = new URL(baseURL);
  const basePath = url.pathname.endsWith("/")
    ? url.pathname.slice(0, -1)
    : url.pathname;
  return `${basePath}/email-challenge/verify`;
};

/**
 * Loads the challenge identified by the browser's signed cookie and verifies
 * the browser binding with a constant-time compare. Returns `null` if anything
 * is off — callers decide whether to treat that as "expired" (poll) or
 * "invalid challenge" (verify-otp).
 */
export const loadChallengeForBrowser = async (
  ctx: GenericEndpointContext,
  cookieName: string,
): Promise<EmailChallengeRecord | null> => {
  const cookie = await readChallengeCookie(ctx, cookieName);
  if (!cookie) return null;

  const record = await ctx.context.adapter.findOne<EmailChallengeRecord>({
    model: EMAIL_CHALLENGE_MODEL,
    where: [{ field: "id", value: cookie.challengeId }],
  });
  if (!record) return null;

  const expectedHash = await sha256Hex(cookie.browserSecret);
  if (!constantTimeEqualHex(expectedHash, record.browserBindingHash))
    return null;

  return record;
};

export const isExpired = (record: EmailChallengeRecord): boolean =>
  new Date(record.expiresAt).getTime() <= Date.now();

/**
 * Atomic state transition. Returns true iff this caller is the unique writer.
 * Use for `pending → approved`, `approved → consuming`, etc.
 *
 * Implementation note: better-auth's `updateMany` returns 0 on the Kysely
 * adapter even when rows are updated (driver doesn't surface a real count),
 * so we use `update` with the predicate baked into `where`. `update` returns
 * the row on a match and `null` when the predicate doesn't match — that's
 * the CAS signal we need.
 */
export const casStatus = async (
  ctx: GenericEndpointContext,
  id: string,
  fromStatus: ChallengeStatus,
  toStatus: ChallengeStatus,
  extra: Partial<Pick<EmailChallengeRecord, "approvedAt" | "consumedAt">> = {},
): Promise<boolean> => {
  const updated = await ctx.context.adapter.update<EmailChallengeRecord>({
    model: EMAIL_CHALLENGE_MODEL,
    where: [
      { field: "id", value: id },
      { field: "status", value: fromStatus },
    ],
    update: {
      status: toStatus,
      ...extra,
      updatedAt: new Date(),
    },
  });
  return updated !== null;
};

/**
 * Best-effort non-atomic status stamp. Use only when:
 * - We've already established uniqueness via CAS, or
 * - The transition is benign on repeat (e.g. stamping `expired`).
 *
 * For the OTP attempt counter use {@link tryIncrementAttempts} instead.
 */
export const updateChallengeStatus = async (
  ctx: GenericEndpointContext,
  id: string,
  patch: Partial<
    Pick<
      EmailChallengeRecord,
      "status" | "attempts" | "approvedAt" | "consumedAt"
    >
  >,
): Promise<void> => {
  await ctx.context.adapter.update<EmailChallengeRecord>({
    model: EMAIL_CHALLENGE_MODEL,
    where: [{ field: "id", value: id }],
    update: { ...patch, updatedAt: new Date() },
  });
};

/**
 * Increments the attempt counter atomically by conditioning on the observed
 * value. Two parallel `verify-otp` calls cannot both increment `4 → 5` —
 * exactly one will succeed; the other gets `false` and must re-read.
 *
 * Returns `false` if someone else moved the counter in between; the caller
 * should treat that as an invalid-attempt response without further increment.
 */
export const tryIncrementAttempts = async (
  ctx: GenericEndpointContext,
  id: string,
  observed: number,
): Promise<boolean> => {
  const updated = await ctx.context.adapter.update<EmailChallengeRecord>({
    model: EMAIL_CHALLENGE_MODEL,
    where: [
      { field: "id", value: id },
      { field: "attempts", value: observed },
    ],
    update: { attempts: observed + 1, updatedAt: new Date() },
  });
  return updated !== null;
};

/**
 * Terminal transition: the challenge will never be useful again. By default,
 * delete the row to match `device-authorization`'s behavior; when the
 * consumer opts into audit retention, stamp it `consumed` instead so the row
 * persists with its full history.
 */
export const terminateChallenge = async (
  ctx: GenericEndpointContext,
  id: string,
  retain: boolean,
): Promise<void> => {
  if (retain) {
    await updateChallengeStatus(ctx, id, {
      status: "consumed",
      consumedAt: new Date(),
    });
    return;
  }
  await ctx.context.adapter.delete({
    model: EMAIL_CHALLENGE_MODEL,
    where: [{ field: "id", value: id }],
  });
};

/**
 * Find an existing user by email or create one. Mirrors the magic-link plugin's
 * behavior: `emailVerified` is set to true because reaching this point requires
 * inbox-ownership proof (a correctly-submitted OTP or an approved link).
 */
export const findOrCreateUser = async (
  ctx: GenericEndpointContext,
  email: string,
  name: string | null | undefined,
  options: Pick<EmailChallengeOptions, "disableSignUp">,
): Promise<{ user: User; isNewUser: boolean }> => {
  const existing = await ctx.context.internalAdapter
    .findUserByEmail(email)
    .then((res) => res?.user);

  if (existing) {
    if (!existing.emailVerified) {
      const updated = await ctx.context.internalAdapter.updateUser(
        existing.id,
        { emailVerified: true },
      );
      return { user: updated as User, isNewUser: false };
    }
    return { user: existing, isNewUser: false };
  }

  if (options.disableSignUp) {
    throw apiError("FORBIDDEN", E.NEW_USER_SIGNUP_DISABLED);
  }

  const created = await ctx.context.internalAdapter.createUser({
    email,
    emailVerified: true,
    name: name ?? "",
  });
  if (!created) {
    throw apiError("BAD_REQUEST", E.FAILED_TO_CREATE_USER);
  }
  return { user: created as User, isNewUser: true };
};

/**
 * Claim the challenge (atomic `approved → consuming`), mint a session, set the
 * session cookie, finalize as terminated, and drop the challenge cookie.
 *
 * Returns `null` if another concurrent caller already claimed this challenge —
 * the caller is responsible for surfacing that as a generic completed/expired
 * response (we do not leak the duplicate-claim).
 */
export const completeChallenge = async (
  ctx: GenericEndpointContext,
  record: EmailChallengeRecord,
  user: User,
  retain: boolean,
  cookieName: string,
): Promise<{
  user: User;
  session: Awaited<
    ReturnType<typeof ctx.context.internalAdapter.createSession>
  >;
} | null> => {
  // Atomic claim. If false, another request beat us to it.
  const claimed = await casStatus(ctx, record.id, "approved", "consuming", {
    consumedAt: new Date(),
  });
  if (!claimed) return null;

  const session = await ctx.context.internalAdapter.createSession(user.id);
  if (!session) {
    throw apiError("BAD_REQUEST", E.FAILED_TO_CREATE_SESSION);
  }
  await setSessionCookie(ctx, { session, user });
  await terminateChallenge(ctx, record.id, retain);
  clearChallengeCookie(ctx, cookieName);
  return { user, session };
};

/**
 * Same as completeChallenge but transitions from `pending → consuming` —
 * used by the same-device OTP flow where the challenge skips the
 * intermediate `approved` state entirely.
 */
export const completeChallengeFromPending = async (
  ctx: GenericEndpointContext,
  record: EmailChallengeRecord,
  user: User,
  retain: boolean,
  cookieName: string,
): Promise<{
  user: User;
  session: Awaited<
    ReturnType<typeof ctx.context.internalAdapter.createSession>
  >;
} | null> => {
  const claimed = await casStatus(ctx, record.id, "pending", "consuming", {
    consumedAt: new Date(),
  });
  if (!claimed) return null;

  const session = await ctx.context.internalAdapter.createSession(user.id);
  if (!session) {
    throw apiError("BAD_REQUEST", E.FAILED_TO_CREATE_SESSION);
  }
  await setSessionCookie(ctx, { session, user });
  await terminateChallenge(ctx, record.id, retain);
  clearChallengeCookie(ctx, cookieName);
  return { user, session };
};
