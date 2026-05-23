# secure-otp-sender-kit

A production-oriented OTP sender and verifier for Node.js.

It is designed for apps that need to send OTP codes by SMS, email, or WhatsApp using a custom provider.

## Security features

- Cryptographically secure OTP generation using Node.js `crypto.randomBytes`
- Rejection-sampling OTP generation to avoid modulo bias
- OTP is stored as HMAC-SHA256 hash, not plaintext
- Per-OTP nonce/salt
- Timing-safe OTP comparison
- OTP expiry
- Single-use OTP; verified OTPs are immediately deleted
- Resend cooldown
- Send rate limiting per identifier
- Verify rate limiting per identifier
- Maximum wrong attempt limit
- Identifier redaction in returned responses
- Pluggable provider abstraction for SMS/email/WhatsApp gateways
- No dependencies

> Important: the included `MemoryStore` is for development, small apps, or single-instance deployments only. For production with multiple servers, implement the store interface using Redis or a database with TTL support.

## Install

```bash
npm install secure-otp-sender-kit
```

## Basic usage

```js
const { OTPSender } = require('secure-otp-sender-kit');

const smsProvider = {
  async send({ identifier, message }) {
    // Call your SMS gateway API here.
    // Do not log the OTP in production.
    console.log('Send SMS to:', identifier);
    console.log('Message:', message);
    return { provider: 'my-sms-gateway', messageId: 'abc123' };
  }
};

const otp = new OTPSender({
  secret: process.env.OTP_SECRET, // at least 32 chars
  issuer: 'Nagar Jatra',
  providers: {
    sms: smsProvider
  },
  defaultChannel: 'sms'
});

await otp.send('+8801712345678', {
  purpose: 'login'
});

const result = await otp.verify('+8801712345678', '123456', {
  purpose: 'login'
});

if (result.ok) {
  console.log('Verified');
} else {
  console.log(result.code, result.message);
}
```

## Express example

```js
const express = require('express');
const { OTPSender, OTPError } = require('secure-otp-sender-kit');

const app = express();
app.use(express.json());

const smsProvider = {
  async send({ identifier, message }) {
    // Replace this with SSL Wireless / Twilio / local SMS gateway call.
    console.log(identifier, message);
    return { provider: 'console-dev' };
  }
};

const otp = new OTPSender({
  secret: process.env.OTP_SECRET,
  issuer: 'My App',
  providers: { sms: smsProvider },
  expiresInMs: 5 * 60 * 1000,
  resendCooldownMs: 60 * 1000,
  maxVerifyAttempts: 5,
  maxSendPerIdentifier: 5
});

app.post('/auth/send-otp', async (req, res) => {
  try {
    const result = await otp.send(req.body.phone, { purpose: 'login' });
    res.json(result);
  } catch (error) {
    if (error instanceof OTPError) {
      return res.status(error.code === 'RATE_LIMITED' ? 429 : 400).json({
        ok: false,
        code: error.code,
        message: error.message,
        meta: error.meta
      });
    }
    res.status(500).json({ ok: false, message: 'Internal server error' });
  }
});

app.post('/auth/verify-otp', async (req, res) => {
  const result = await otp.verify(req.body.phone, req.body.code, { purpose: 'login' });
  res.status(result.ok ? 200 : 400).json(result);
});
```

## Provider interface

A provider is any object with a `send()` function:

```js
const provider = {
  async send({ identifier, message, code, channel, purpose, expiresAt, metadata }) {
    // Send SMS/email/WhatsApp here.
    return { provider: 'custom', messageId: 'provider-message-id' };
  }
};
```

For security, avoid logging `code` in production. The provider receives `code` only because some gateways require templated payloads. Prefer sending the already-built `message` when possible.

## Redis store idea

For production, use Redis with TTL. Your store should implement:

```ts
interface OTPStore {
  get(key: string): Promise<any>;
  set(key: string, value: any): Promise<void>;
  delete(key: string): Promise<void>;
  incrementCounter(key: string, windowMs: number, now?: number): Promise<{ count: number; resetAt: number }>;
}
```

Use atomic Redis commands for counters to prevent race conditions.

## Publish

```bash
npm login
npm publish
```

If the package name is already taken, rename it in `package.json`, for example:

```json
{
  "name": "@yourusername/secure-otp-sender-kit"
}
```

Then publish:

```bash
npm publish --access public
```
