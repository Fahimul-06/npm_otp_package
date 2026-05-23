export type OTPChannel = 'sms' | 'email' | 'whatsapp';

export interface OTPProviderSendPayload {
  identifier: string;
  channel: OTPChannel;
  message: string;
  code: string;
  purpose: string;
  expiresAt: number;
  metadata: Record<string, unknown>;
}

export interface OTPProvider {
  send(payload: OTPProviderSendPayload): Promise<Record<string, unknown>>;
}

export interface StoreCounter {
  count: number;
  resetAt: number;
}

export interface OTPStore {
  get(key: string): Promise<any>;
  set(key: string, value: any): Promise<void>;
  delete(key: string): Promise<void>;
  incrementCounter(key: string, windowMs: number, now?: number): Promise<StoreCounter>;
}

export interface OTPSenderOptions {
  secret: string;
  providers: Partial<Record<OTPChannel, OTPProvider>>;
  store?: OTPStore;
  defaultChannel?: OTPChannel;
  length?: number;
  expiresInMs?: number;
  resendCooldownMs?: number;
  maxVerifyAttempts?: number;
  maxSendPerIdentifier?: number;
  sendWindowMs?: number;
  maxVerifyPerIdentifier?: number;
  verifyWindowMs?: number;
  minimumSecretLength?: number;
  codeAlphabet?: string;
  purpose?: string;
  issuer?: string;
  messageBuilder?: (input: {
    code: string;
    identifier: string;
    channel: OTPChannel;
    purpose: string;
    expiresInMinutes: number;
    issuer: string;
  }) => string;
  keyBuilder?: (input: {
    identifier: string;
    channel: OTPChannel;
    purpose: string;
  }) => string;
  logger?: { info?: (message: string, meta?: Record<string, unknown>) => void } | null;
}

export interface SendOptions {
  channel?: OTPChannel;
  purpose?: string;
  length?: number;
  expiresInMs?: number;
  maxVerifyAttempts?: number;
  message?: string;
  metadata?: Record<string, unknown>;
  now?: number;
}

export interface VerifyOptions {
  channel?: OTPChannel;
  purpose?: string;
  now?: number;
}

export interface RevokeOptions {
  channel?: OTPChannel;
  purpose?: string;
}

export class OTPError extends Error {
  code: string;
  meta: Record<string, unknown>;
}

export class MemoryStore implements OTPStore {
  get(key: string): Promise<any>;
  set(key: string, value: any): Promise<void>;
  delete(key: string): Promise<void>;
  incrementCounter(key: string, windowMs: number, now?: number): Promise<StoreCounter>;
  clearExpired(now?: number): Promise<void>;
}

export class ConsoleProvider implements OTPProvider {
  send(payload: OTPProviderSendPayload): Promise<Record<string, unknown>>;
}

export class NoopProvider implements OTPProvider {
  send(payload: OTPProviderSendPayload): Promise<Record<string, unknown>>;
}

export class OTPSender {
  constructor(options: OTPSenderOptions);
  send(identifier: string, options?: SendOptions): Promise<{
    ok: true;
    channel: OTPChannel;
    identifier: string;
    expiresAt: number;
    resendAfterMs: number;
    providerResult?: Record<string, unknown>;
  }>;
  verify(identifier: string, code: string, options?: VerifyOptions): Promise<{
    ok: boolean;
    code: string;
    message: string;
    remainingAttempts?: number;
  }>;
  revoke(identifier: string, options?: RevokeOptions): Promise<{ ok: true }>;
}

export const ERROR_CODES: Record<string, string>;
export function generateSecureCode(length?: number, alphabet?: string): string;
export function hashOtp(input: {
  secret: string;
  identifier: string;
  channel: OTPChannel;
  purpose: string;
  code: string;
  nonce: string;
}): string;
export function redactIdentifier(identifier: string): string;
