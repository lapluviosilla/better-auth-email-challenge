import type { BetterAuthPluginDBSchema } from "better-auth";

export const EMAIL_CHALLENGE_MODEL = "emailChallenge" as const;

export const schema = {
  emailChallenge: {
    fields: {
      email: { type: "string", required: true },
      hashedApprovalToken: { type: "string", required: true, unique: true },
      hashedOtp: { type: "string", required: true },
      browserBindingHash: { type: "string", required: true },
      status: { type: "string", required: true },
      attempts: { type: "number", required: true, defaultValue: 0 },
      name: { type: "string", required: false },
      callbackURL: { type: "string", required: false },
      ipAddress: { type: "string", required: false },
      userAgent: { type: "string", required: false },
      expiresAt: { type: "date", required: true },
      approvedAt: { type: "date", required: false },
      consumedAt: { type: "date", required: false },
      createdAt: { type: "date", required: true },
      updatedAt: { type: "date", required: true },
    },
  },
} satisfies BetterAuthPluginDBSchema;

/**
 * `consuming` is a transient state between `approved` and `consumed` used to
 * make session-mint atomic — only the writer that wins the
 * `approved → consuming` CAS proceeds to create a session. Not exposed to
 * clients.
 */
export type ChallengeStatus =
  | "pending"
  | "approved"
  | "consuming"
  | "consumed"
  | "expired"
  | "canceled";

export interface EmailChallengeRecord {
  id: string;
  email: string;
  hashedApprovalToken: string;
  hashedOtp: string;
  browserBindingHash: string;
  status: ChallengeStatus;
  attempts: number;
  name?: string | null;
  callbackURL?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  expiresAt: Date;
  approvedAt?: Date | null;
  consumedAt?: Date | null;
  createdAt: Date;
  updatedAt: Date;
}
