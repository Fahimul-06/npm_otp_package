'use strict';

const crypto = require('crypto');

const DEFAULTS = Object.freeze({
  length: 6,
  expiresInMs: 5 * 60 * 1000,
  resendCooldownMs: 60 * 1000,
  maxVerifyAttempts: 5,
  maxSendPerIdentifier: 5,
  sendWindowMs: 15 * 60 * 1000,
  maxVerifyPerIdentifier: 20,
  verifyWindowMs: 15 * 60 * 1000,
  minimumSecretLength: 32,
  codeAlphabet: '0123456789',
  purpose: 'otp',
  issuer: 'secure-otp-sender-kit',
  messageBuilder: ({ code, expiresInMinutes, issuer }) => `${issuer} verification code is ${code}. It expires in ${expiresInMinutes} minutes. Do not share this code.`,
  keyBuilder: ({ identifier, channel, purpose }) => `${purpose}:${channel}:${normalizeIdentifier(identifier)}`,
  logger: null
});

const ERROR_CODES = Object.freeze({
  INVALID_IDENTIFIER: 'INVALID_IDENTIFIER',
  INVALID_CHANNEL: 'INVALID_CHANNEL',
  MISSING_PROVIDER: 'MISSING_PROVIDER',
  RATE_LIMITED: 'RATE_LIMITED',
  COOLDOWN_ACTIVE: 'COOLDOWN_ACTIVE',
  SEND_FAILED: 'SEND_FAILED',
  OTP_NOT_FOUND: 'OTP_NOT_FOUND',
  OTP_EXPIRED: 'OTP_EXPIRED',
  OTP_USED: 'OTP_USED',
  OTP_LOCKED: 'OTP_LOCKED',
  OTP_INVALID: 'OTP_INVALID',
  SECRET_TOO_SHORT: 'SECRET_TOO_SHORT'
});

class OTPError extends Error {
  constructor(code, message, meta = {}) {
    super(message);
    this.name = 'OTPError';
    this.code = code;
    this.meta = meta;
  }
}

class MemoryStore {
  constructor() {
    this.records = new Map();
    this.counters = new Map();
  }

  async get(key) {
    return this.records.get(key) || null;
  }

  async set(key, value) {
    this.records.set(key, value);
  }

  async delete(key) {
    this.records.delete(key);
  }

  async incrementCounter(key, windowMs, now = Date.now()) {
    const current = this.counters.get(key);
    if (!current || current.resetAt <= now) {
      const next = { count: 1, resetAt: now + windowMs };
      this.counters.set(key, next);
      return next;
    }
    current.count += 1;
    this.counters.set(key, current);
    return current;
  }

  async clearExpired(now = Date.now()) {
    for (const [key, record] of this.records.entries()) {
      if (record.expiresAt <= now) this.records.delete(key);
    }
    for (const [key, counter] of this.counters.entries()) {
      if (counter.resetAt <= now) this.counters.delete(key);
    }
  }
}

class ConsoleProvider {
  async send({ identifier, message, channel }) {
    console.log(`[OTP:${channel}] ${identifier}: ${message}`);
    return { provider: 'console', messageId: `console_${Date.now()}` };
  }
}

class NoopProvider {
  async send() {
    return { provider: 'noop', messageId: `noop_${Date.now()}` };
  }
}

function normalizeIdentifier(identifier) {
  if (typeof identifier !== 'string') return '';
  return identifier.trim().toLowerCase();
}

function assertSecret(secret, minimumSecretLength) {
  if (typeof secret !== 'string' || secret.length < minimumSecretLength) {
    throw new OTPError(
      ERROR_CODES.SECRET_TOO_SHORT,
      `OTP secret must be a string with at least ${minimumSecretLength} characters.`
    );
  }
}

function validateIdentifier(identifier, channel) {
  const value = normalizeIdentifier(identifier);
  if (!value) {
    throw new OTPError(ERROR_CODES.INVALID_IDENTIFIER, 'Identifier is required.');
  }

  if (channel === 'sms') {
    if (!/^\+?[1-9]\d{7,14}$/.test(value.replace(/[\s-]/g, ''))) {
      throw new OTPError(ERROR_CODES.INVALID_IDENTIFIER, 'SMS identifier must be an E.164-like phone number.');
    }
  }

  if (channel === 'email') {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
      throw new OTPError(ERROR_CODES.INVALID_IDENTIFIER, 'Email identifier is invalid.');
    }
  }

  return value;
}

function generateSecureCode(length = DEFAULTS.length, alphabet = DEFAULTS.codeAlphabet) {
  if (!Number.isInteger(length) || length < 4 || length > 12) {
    throw new TypeError('OTP length must be an integer between 4 and 12.');
  }
  if (typeof alphabet !== 'string' || alphabet.length < 2) {
    throw new TypeError('OTP alphabet must contain at least two characters.');
  }

  let code = '';
  const maxValid = Math.floor(256 / alphabet.length) * alphabet.length;

  while (code.length < length) {
    const bytes = crypto.randomBytes(length);
    for (const byte of bytes) {
      if (byte < maxValid) {
        code += alphabet[byte % alphabet.length];
        if (code.length === length) break;
      }
    }
  }

  return code;
}

function hashOtp({ secret, identifier, channel, purpose, code, nonce }) {
  return crypto
    .createHmac('sha256', secret)
    .update(`${purpose}:${channel}:${normalizeIdentifier(identifier)}:${nonce}:${code}`)
    .digest('hex');
}

function timingSafeEqualHex(a, b) {
  const ab = Buffer.from(String(a || ''), 'hex');
  const bb = Buffer.from(String(b || ''), 'hex');
  if (ab.length !== bb.length || ab.length === 0) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function redactIdentifier(identifier) {
  const normalized = normalizeIdentifier(identifier);
  if (normalized.includes('@')) {
    const [name, domain] = normalized.split('@');
    return `${name.slice(0, 2)}***@${domain}`;
  }
  return `${normalized.slice(0, 3)}***${normalized.slice(-2)}`;
}

class OTPSender {
  constructor(options = {}) {
    this.options = { ...DEFAULTS, ...options };
    assertSecret(this.options.secret, this.options.minimumSecretLength);
    this.store = options.store || new MemoryStore();
    this.providers = options.providers || {};
    this.defaultChannel = options.defaultChannel || 'sms';
  }

  providerFor(channel) {
    const provider = this.providers[channel];
    if (!provider || typeof provider.send !== 'function') {
      throw new OTPError(ERROR_CODES.MISSING_PROVIDER, `No provider configured for channel: ${channel}`);
    }
    return provider;
  }

  makeKey(identifier, channel, purpose) {
    return this.options.keyBuilder({ identifier, channel, purpose });
  }

  async send(identifier, sendOptions = {}) {
    const now = sendOptions.now || Date.now();
    const channel = sendOptions.channel || this.defaultChannel;
    if (!['sms', 'email', 'whatsapp'].includes(channel)) {
      throw new OTPError(ERROR_CODES.INVALID_CHANNEL, 'Channel must be sms, email, or whatsapp.');
    }

    const normalized = validateIdentifier(identifier, channel === 'whatsapp' ? 'sms' : channel);
    const purpose = sendOptions.purpose || this.options.purpose;
    const key = this.makeKey(normalized, channel, purpose);
    const rateKey = `send:${key}`;

    const counter = await this.store.incrementCounter(rateKey, this.options.sendWindowMs, now);
    if (counter.count > this.options.maxSendPerIdentifier) {
      throw new OTPError(ERROR_CODES.RATE_LIMITED, 'Too many OTP send requests. Try again later.', {
        retryAfterMs: counter.resetAt - now
      });
    }

    const existing = await this.store.get(key);
    if (existing && existing.lastSentAt && now - existing.lastSentAt < this.options.resendCooldownMs) {
      throw new OTPError(ERROR_CODES.COOLDOWN_ACTIVE, 'OTP was sent recently. Wait before requesting another OTP.', {
        retryAfterMs: this.options.resendCooldownMs - (now - existing.lastSentAt)
      });
    }

    const code = generateSecureCode(sendOptions.length || this.options.length, this.options.codeAlphabet);
    const nonce = crypto.randomBytes(16).toString('hex');
    const hash = hashOtp({
      secret: this.options.secret,
      identifier: normalized,
      channel,
      purpose,
      code,
      nonce
    });

    const expiresInMs = sendOptions.expiresInMs || this.options.expiresInMs;
    const expiresAt = now + expiresInMs;
    const expiresInMinutes = Math.ceil(expiresInMs / 60000);
    const message = sendOptions.message || this.options.messageBuilder({
      code,
      identifier: normalized,
      channel,
      purpose,
      expiresInMinutes,
      issuer: this.options.issuer
    });

    const provider = this.providerFor(channel);
    let providerResult;
    try {
      providerResult = await provider.send({
        identifier: normalized,
        channel,
        message,
        code,
        purpose,
        expiresAt,
        metadata: sendOptions.metadata || {}
      });
    } catch (error) {
      throw new OTPError(ERROR_CODES.SEND_FAILED, 'OTP provider failed to send the message.', {
        cause: error && error.message ? error.message : String(error)
      });
    }

    await this.store.set(key, {
      hash,
      nonce,
      purpose,
      channel,
      identifier: normalized,
      createdAt: now,
      lastSentAt: now,
      expiresAt,
      attempts: 0,
      maxAttempts: sendOptions.maxVerifyAttempts || this.options.maxVerifyAttempts,
      usedAt: null,
      providerResult
    });

    if (this.options.logger && typeof this.options.logger.info === 'function') {
      this.options.logger.info('OTP sent', {
        identifier: redactIdentifier(normalized),
        channel,
        purpose,
        expiresAt,
        provider: providerResult && providerResult.provider
      });
    }

    return {
      ok: true,
      channel,
      identifier: redactIdentifier(normalized),
      expiresAt,
      resendAfterMs: this.options.resendCooldownMs,
      providerResult
    };
  }

  async verify(identifier, code, verifyOptions = {}) {
    const now = verifyOptions.now || Date.now();
    const channel = verifyOptions.channel || this.defaultChannel;
    const normalized = validateIdentifier(identifier, channel === 'whatsapp' ? 'sms' : channel);
    const purpose = verifyOptions.purpose || this.options.purpose;
    const key = this.makeKey(normalized, channel, purpose);
    const verifyRateKey = `verify:${key}`;

    const counter = await this.store.incrementCounter(verifyRateKey, this.options.verifyWindowMs, now);
    if (counter.count > this.options.maxVerifyPerIdentifier) {
      throw new OTPError(ERROR_CODES.RATE_LIMITED, 'Too many OTP verification attempts. Try again later.', {
        retryAfterMs: counter.resetAt - now
      });
    }

    const record = await this.store.get(key);
    if (!record) {
      return { ok: false, code: ERROR_CODES.OTP_NOT_FOUND, message: 'OTP not found or already consumed.' };
    }

    if (record.usedAt) {
      await this.store.delete(key);
      return { ok: false, code: ERROR_CODES.OTP_USED, message: 'OTP was already used.' };
    }

    if (record.expiresAt <= now) {
      await this.store.delete(key);
      return { ok: false, code: ERROR_CODES.OTP_EXPIRED, message: 'OTP expired.' };
    }

    if (record.attempts >= record.maxAttempts) {
      await this.store.delete(key);
      return { ok: false, code: ERROR_CODES.OTP_LOCKED, message: 'Too many invalid attempts.' };
    }

    const candidateHash = hashOtp({
      secret: this.options.secret,
      identifier: normalized,
      channel,
      purpose,
      code: String(code || '').trim(),
      nonce: record.nonce
    });

    const valid = timingSafeEqualHex(record.hash, candidateHash);

    if (!valid) {
      record.attempts += 1;
      await this.store.set(key, record);
      return {
        ok: false,
        code: ERROR_CODES.OTP_INVALID,
        message: 'Invalid OTP.',
        remainingAttempts: Math.max(record.maxAttempts - record.attempts, 0)
      };
    }

    record.usedAt = now;
    await this.store.delete(key);

    return {
      ok: true,
      code: 'OTP_VERIFIED',
      message: 'OTP verified successfully.'
    };
  }

  async revoke(identifier, options = {}) {
    const channel = options.channel || this.defaultChannel;
    const normalized = validateIdentifier(identifier, channel === 'whatsapp' ? 'sms' : channel);
    const purpose = options.purpose || this.options.purpose;
    await this.store.delete(this.makeKey(normalized, channel, purpose));
    return { ok: true };
  }
}

module.exports = {
  OTPSender,
  MemoryStore,
  ConsoleProvider,
  NoopProvider,
  OTPError,
  ERROR_CODES,
  generateSecureCode,
  hashOtp,
  redactIdentifier
};
