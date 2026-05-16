import { generateRandomString } from "better-auth/crypto";

export const sha256Hex = async (input: string): Promise<string> => {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
};

export const generateApprovalToken = (): string =>
  generateRandomString(32, "a-z", "A-Z", "0-9");

export const generateBrowserSecret = (): string =>
  generateRandomString(32, "a-z", "A-Z", "0-9");

export const generateOtp = (length: number): string =>
  generateRandomString(length, "0-9");

/**
 * Constant-time equality for two equal-length hex strings.
 *
 * Inputs are SHA-256 hex digests in our codebase, so the secrets they're
 * derived from are not recoverable even if comparison timing leaked the
 * digest. We still use this for defense in depth: it costs ~nothing and
 * keeps the bar consistent if anyone ever feeds a non-hash value through.
 */
export const constantTimeEqualHex = (a: string, b: string): boolean => {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
};
