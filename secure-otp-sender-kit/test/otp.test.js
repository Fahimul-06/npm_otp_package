'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  OTPSender,
  NoopProvider,
  OTPError,
  ERROR_CODES,
  generateSecureCode
} = require('../src');

const SECRET = 'this-is-a-very-secure-test-secret-with-32chars';

class CaptureProvider {
  constructor() {
    this.messages = [];
  }
  async send(payload) {
    this.messages.push(payload);
    return { provider: 'capture', messageId: String(this.messages.length) };
  }
}

test('generateSecureCode creates correct numeric length', () => {
  const code = generateSecureCode(6);
  assert.match(code, /^\d{6}$/);
});

test('send and verify valid OTP', async () => {
  const provider = new CaptureProvider();
  const sender = new OTPSender({
    secret: SECRET,
    providers: { sms: provider }
  });

  const sendResult = await sender.send('+8801712345678');
  assert.equal(sendResult.ok, true);
  assert.equal(provider.messages.length, 1);

  const code = provider.messages[0].code;
  const verifyResult = await sender.verify('+8801712345678', code);
  assert.equal(verifyResult.ok, true);
});

test('OTP cannot be reused', async () => {
  const provider = new CaptureProvider();
  const sender = new OTPSender({ secret: SECRET, providers: { sms: provider } });

  await sender.send('+8801712345678');
  const code = provider.messages[0].code;

  assert.equal((await sender.verify('+8801712345678', code)).ok, true);
  const second = await sender.verify('+8801712345678', code);
  assert.equal(second.ok, false);
  assert.equal(second.code, ERROR_CODES.OTP_NOT_FOUND);
});

test('wrong OTP counts attempts and locks', async () => {
  const provider = new CaptureProvider();
  const sender = new OTPSender({
    secret: SECRET,
    providers: { sms: provider },
    maxVerifyAttempts: 2
  });

  await sender.send('+8801712345678');

  const first = await sender.verify('+8801712345678', '000000');
  assert.equal(first.ok, false);
  assert.equal(first.code, ERROR_CODES.OTP_INVALID);
  assert.equal(first.remainingAttempts, 1);

  const second = await sender.verify('+8801712345678', '111111');
  assert.equal(second.ok, false);
  assert.equal(second.remainingAttempts, 0);

  const third = await sender.verify('+8801712345678', '222222');
  assert.equal(third.ok, false);
  assert.equal(third.code, ERROR_CODES.OTP_LOCKED);
});

test('expired OTP fails', async () => {
  const provider = new CaptureProvider();
  const sender = new OTPSender({
    secret: SECRET,
    providers: { sms: provider },
    expiresInMs: 1000
  });

  await sender.send('+8801712345678', { now: 1000 });
  const code = provider.messages[0].code;
  const result = await sender.verify('+8801712345678', code, { now: 3000 });

  assert.equal(result.ok, false);
  assert.equal(result.code, ERROR_CODES.OTP_EXPIRED);
});

test('resend cooldown blocks repeated sends', async () => {
  const sender = new OTPSender({
    secret: SECRET,
    providers: { sms: new NoopProvider() },
    resendCooldownMs: 60000
  });

  await sender.send('+8801712345678', { now: 1000 });

  await assert.rejects(
    sender.send('+8801712345678', { now: 2000 }),
    (error) => error instanceof OTPError && error.code === ERROR_CODES.COOLDOWN_ACTIVE
  );
});

test('send rate limit blocks repeated abuse', async () => {
  const sender = new OTPSender({
    secret: SECRET,
    providers: { sms: new NoopProvider() },
    resendCooldownMs: 0,
    maxSendPerIdentifier: 2,
    sendWindowMs: 60000
  });

  await sender.send('+8801712345678', { now: 1000 });
  await sender.send('+8801712345678', { now: 2000 });

  await assert.rejects(
    sender.send('+8801712345678', { now: 3000 }),
    (error) => error instanceof OTPError && error.code === ERROR_CODES.RATE_LIMITED
  );
});

test('short secret is rejected', () => {
  assert.throws(
    () => new OTPSender({ secret: 'short', providers: { sms: new NoopProvider() } }),
    (error) => error instanceof OTPError && error.code === ERROR_CODES.SECRET_TOO_SHORT
  );
});
