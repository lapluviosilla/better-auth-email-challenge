import type { GenericEndpointContext } from "better-auth";

const SEPARATOR = "|";

export const encodeChallengeCookie = (
  challengeId: string,
  browserSecret: string,
): string => `${challengeId}${SEPARATOR}${browserSecret}`;

// Format: <challengeId>|<browserSecret>. Strict parse so a future change in
// either field's charset doesn't silently turn this into a parse-oracle.
const SECRET_RE = /^[A-Za-z0-9]{32}$/;
// IDs are framework-generated; we don't pin a regex but require non-empty.
export const decodeChallengeCookie = (
  raw: string,
): { challengeId: string; browserSecret: string } | null => {
  const parts = raw.split(SEPARATOR);
  if (parts.length !== 2) return null;
  const [challengeId, browserSecret] = parts as [string, string];
  if (!challengeId) return null;
  if (!SECRET_RE.test(browserSecret)) return null;
  return { challengeId, browserSecret };
};

export const setChallengeCookie = async (
  ctx: GenericEndpointContext,
  cookieName: string,
  challengeId: string,
  browserSecret: string,
  expiresIn: number,
): Promise<void> => {
  const cookie = ctx.context.createAuthCookie(cookieName, {
    maxAge: expiresIn,
  });
  await ctx.setSignedCookie(
    cookie.name,
    encodeChallengeCookie(challengeId, browserSecret),
    ctx.context.secret,
    cookie.attributes,
  );
};

export const clearChallengeCookie = (
  ctx: GenericEndpointContext,
  cookieName: string,
): void => {
  const cookie = ctx.context.createAuthCookie(cookieName);
  ctx.setCookie(cookie.name, "", { ...cookie.attributes, maxAge: 0 });
};

export const readChallengeCookie = async (
  ctx: GenericEndpointContext,
  cookieName: string,
): Promise<{ challengeId: string; browserSecret: string } | null> => {
  const cookie = ctx.context.createAuthCookie(cookieName);
  const raw = await ctx.getSignedCookie(cookie.name, ctx.context.secret);
  if (!raw || typeof raw !== "string") return null;
  return decodeChallengeCookie(raw);
};
