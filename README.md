# JWT (JSON Web Token)

---

## Table of Contents

1. [What is JWT?](#1-what-is-jwt)
2. [Why JWT?](#2-why-jwt)
3. [JWT Structure](#3-jwt-structure)
4. [Claims — Types & Reference](#4-claims--types--reference)
5. [Signing Algorithms](#5-signing-algorithms)
6. [How JWT Works — Auth Flow](#6-how-jwt-works--auth-flow)
7. [Implementing JWT](#7-implementing-jwt)
8. [Where to Store JWT on Client](#8-where-to-store-jwt-on-client)
9. [Access Tokens & Refresh Tokens](#9-access-tokens--refresh-tokens)
10. [JTI — JWT ID](#10-jti--jwt-id)
11. [Token Revocation Strategies](#11-token-revocation-strategies)
12. [JWE — JSON Web Encryption](#12-jwe--json-web-encryption)
13. [JWKS — JSON Web Key Set](#13-jwks--json-web-key-set)
14. [Security Vulnerabilities & Attacks](#14-security-vulnerabilities--attacks)
15. [Security Best Practices Checklist](#15-security-best-practices-checklist)
16. [JWT vs Sessions vs OAuth](#16-jwt-vs-sessions-vs-oauth)
17. [JWT in Microservices](#17-jwt-in-microservices)
18. [Common Error Handling](#18-common-error-handling)
19. [Debugging JWT](#19-debugging-jwt)
20. [Quick Reference](#20-quick-reference)

---

## 1. What is JWT?

JWT (pronounced **"jot"**) is an open standard — [RFC 7519](https://tools.ietf.org/html/rfc7519) — that defines a compact, self-contained way to securely transmit information between parties as a JSON object.

```
JWT = a digitally signed JSON payload, encoded as a URL-safe string
```

Key characteristics:

| Property | Description |
|---|---|
| **Compact** | Small enough to send in URL, POST body, or HTTP header |
| **Self-contained** | Carries all necessary information inside itself |
| **Digitally signed** | Integrity can be verified — tampering is detectable |
| **Stateless** | Server needs no session storage to validate |

> JWT is part of the **JOSE** (JSON Object Signing and Encryption) family of standards, which includes JWS, JWE, JWK, and JWA.

---

## 2. Why JWT?

### Traditional Session-Based Auth

```
1. User logs in
2. Server creates a session → stores it in DB/memory
3. Server sends session ID in a cookie
4. Every request → server looks up session in DB
```

Problems:
- Server must store sessions — memory pressure
- Hard to scale horizontally (multiple servers need shared session store)
- Not suitable for stateless APIs or microservices

### JWT-Based Auth

```
1. User logs in
2. Server issues a signed JWT
3. Client stores it and sends it with every request
4. Server verifies the signature — no DB lookup needed
```

Benefits:
- Stateless — no server-side storage required
- Scales horizontally with ease
- Works across domains (CORS-friendly)
- Self-contained — user info embedded in token

---

## 3. JWT Structure

A JWT is three Base64URL-encoded parts joined by dots:

```
HEADER.PAYLOAD.SIGNATURE
```

Real token:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.eyJzdWIiOiJ1c2VyMTIzIiwibmFtZSI6IkFsaWNlIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzEwMDAwMDAwLCJleHAiOjE3MTAwMDM2MDB9
.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

---

### Part 1: Header

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

| Field | Description |
|---|---|
| `alg` | Signing/encryption algorithm used |
| `typ` | Token type — always `"JWT"` |
| `kid` | Key ID — identifies which key was used (optional, useful with JWKS) |

---

### Part 2: Payload

```json
{
  "sub": "user123",
  "name": "Alice",
  "role": "admin",
  "iat": 1710000000,
  "exp": 1710003600,
  "jti": "550e8400-e29b-41d4-a716-446655440000"
}
```

> The payload is Base64URL encoded — NOT encrypted.
> Anyone with the token can decode and read it.
> Never put passwords, secrets, or sensitive personal data here (unless using JWE).

---

### Part 3: Signature

For `HS256`:
```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

For `RS256`:
```
RSASHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  privateKey
)
```

Purpose: Proves the token was issued by a trusted party and has not been modified.

---

## 4. Claims — Types & Reference

Claims are statements about the subject (user/entity). There are three categories:

### Registered Claims (Standard — RFC 7519)

| Claim | Name | Type | Description |
|---|---|---|---|
| `iss` | Issuer | String/URI | Who issued the token (e.g., `"https://auth.myapp.com"`) |
| `sub` | Subject | String | Who the token is about (usually user ID) |
| `aud` | Audience | String/Array | Who the token is intended for |
| `exp` | Expiration | Number (Unix) | Token is invalid after this time |
| `nbf` | Not Before | Number (Unix) | Token is invalid before this time |
| `iat` | Issued At | Number (Unix) | When the token was created |
| `jti` | JWT ID | String | Unique identifier for this token |

### Public Claims

Registered in the [IANA JWT Claims Registry](https://www.iana.org/assignments/jwt/jwt.xhtml) to avoid naming collisions when sharing between organizations.

### Private Claims

Custom claims agreed upon between your producer and consumer:

```json
{
  "role": "admin",
  "tenant_id": "org_456",
  "permissions": ["read", "write", "delete"],
  "department": "engineering"
}
```

### Claims Best Practices

- Always include `exp` — tokens without expiry are a critical vulnerability
- Always include `iat` — helps with token age checks
- Include `iss` and `aud` — validate them on every request
- Include `jti` when you need revocation capability
- Use short, collision-safe names for custom claims
- Keep the payload small — it goes in every request header

---

## 5. Signing Algorithms

### Symmetric — HMAC (Shared Secret)

```
HS256  → HMAC + SHA-256  (most common)
HS384  → HMAC + SHA-384
HS512  → HMAC + SHA-512
```

How it works:
```
Sign:   HMAC(header.payload, secret) → token
Verify: HMAC(header.payload, secret) → must match signature
```

Same secret used for both signing and verifying.

When to use:
- Single server application
- Internal service-to-service communication
- When both parties can securely share a secret

---

### Asymmetric — RSA

```
RS256  → RSA + SHA-256
RS384  → RSA + SHA-384
RS512  → RSA + SHA-512

PS256  → RSA-PSS + SHA-256 (more secure variant)
PS384  → RSA-PSS + SHA-384
PS512  → RSA-PSS + SHA-512
```

How it works:
```
Sign:   RSA_sign(header.payload, privateKey) → token
Verify: RSA_verify(header.payload, publicKey) → valid/invalid
```

When to use:
- Microservices (services only need public key to verify)
- Third-party token consumption
- When private key must stay on auth server only

---

### Asymmetric — ECDSA (Elliptic Curve)

```
ES256  → ECDSA + P-256 + SHA-256
ES384  → ECDSA + P-384 + SHA-384
ES512  → ECDSA + P-521 + SHA-512
```

Why prefer over RSA:
- Smaller key sizes (256-bit EC ≈ 3072-bit RSA in security)
- Faster signing and verification
- Smaller token size

When to use:
- Mobile applications (performance matters)
- IoT devices
- High-throughput APIs

---

### Algorithm Comparison

| Algorithm | Type | Speed | Key Size | Token Size | Recommended |
|---|---|---|---|---|---|
| `HS256` | Symmetric | Fastest | 256-bit secret | Smallest | Yes (simple use) |
| `RS256` | Asymmetric | Slow | 2048-bit+ key | Larger | Yes (distributed) |
| `ES256` | Asymmetric | Fast | 256-bit key | Medium | Yes (best balance) |
| `RS512` | Asymmetric | Slowest | 2048-bit+ key | Largest | Situational |
| `none` | None | — | None | — | NEVER |

---

## 6. How JWT Works — Auth Flow

### Basic Authentication Flow

```
┌──────────┐                               ┌────────────────┐
│  Client  │                               │  Auth Server   │
└────┬─────┘                               └───────┬────────┘
     │                                             │
     │   POST /login                               │
     │   { "email": "alice@example.com",           │
     │     "password": "secret123" }               │
     │  ─────────────────────────────────────────► │
     │                                             │ 1. Validate credentials
     │                                             │ 2. Create JWT payload
     │                                             │ 3. Sign with secret/key
     │                                             │ 4. Return token
     │   { "token": "eyJ..." }                     │
     │  ◄───────────────────────────────────────── │
     │                                             │
     │   Store token (memory/cookie)               │
     │                                             │
     │   GET /api/profile                          │
     │   Authorization: Bearer eyJ...              │
     │  ─────────────────────────────────────────► │
     │                                             │ 5. Decode header + payload
     │                                             │ 6. Verify signature
     │                                             │ 7. Check exp, iss, aud
     │                                             │ 8. Extract user info
     │   { "user": { "name": "Alice", ... } }      │
     │  ◄───────────────────────────────────────── │
```

### What the Server Validates on Every Request

```
1. Is the signature valid?            → Verify using secret/public key
2. Has the token expired?             → Check exp > current time
3. Is the issuer trusted?             → Check iss matches expected value
4. Is the audience correct?           → Check aud matches this service
5. Is the token active yet?           → Check nbf <= current time
6. Has the token been revoked?        → Check jti against blocklist (if used)
```

---

## 7. Implementing JWT

### Node.js — `jsonwebtoken`

```bash
npm install jsonwebtoken
```

**Sign a token:**
```js
const jwt = require('jsonwebtoken');

const token = jwt.sign(
  {
    sub: 'user123',
    name: 'Alice',
    role: 'admin',
    aud: 'myapp-api'
  },
  process.env.JWT_SECRET,
  {
    expiresIn: '15m',      // access token — short lived
    issuer: 'myapp-auth',
    algorithm: 'HS256'
  }
);
```

**Verify a token:**
```js
try {
  const decoded = jwt.verify(token, process.env.JWT_SECRET, {
    algorithms: ['HS256'],      // explicitly whitelist algorithm
    issuer: 'myapp-auth',
    audience: 'myapp-api'
  });

  console.log(decoded.sub);    // 'user123'
  console.log(decoded.role);   // 'admin'
} catch (err) {
  if (err.name === 'TokenExpiredError') {
    // token is expired — prompt refresh
  } else if (err.name === 'JsonWebTokenError') {
    // invalid token — reject request
  } else if (err.name === 'NotBeforeError') {
    // token not yet active
  }
}
```

**Decode without verifying (read only):**
```js
// WARNING: This does NOT verify the signature
// Use only when you trust the token origin or don't need security
const decoded = jwt.decode(token, { complete: true });
console.log(decoded.header);   // { alg: 'HS256', typ: 'JWT' }
console.log(decoded.payload);  // { sub: 'user123', ... }
```

---

### Express.js Middleware

```js
const jwt = require('jsonwebtoken');

function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer <token>"

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'myapp-auth'
    });
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Role-based access
function authorize(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// Usage
app.get('/api/profile', authenticate, (req, res) => {
  res.json({ user: req.user });
});

app.delete('/api/users/:id', authenticate, authorize('admin'), (req, res) => {
  // only admins reach here
});
```

---

### Python — `PyJWT`

```bash
pip install PyJWT
```

```python
import jwt
import datetime

SECRET_KEY = "your-secret-key"

# Sign
token = jwt.encode(
    {
        "sub": "user123",
        "role": "admin",
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    },
    SECRET_KEY,
    algorithm="HS256"
)

# Verify
try:
    decoded = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"],
        options={"require": ["exp", "iat", "sub"]}
    )
    print(decoded["sub"])  # 'user123'
except jwt.ExpiredSignatureError:
    print("Token expired")
except jwt.InvalidTokenError:
    print("Invalid token")
```

---

### RSA Key Pair (Asymmetric) — Node.js

```bash
# Generate keys
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

```js
const fs = require('fs');

const privateKey = fs.readFileSync('./private.pem');
const publicKey  = fs.readFileSync('./public.pem');

// Sign with private key (auth server)
const token = jwt.sign(
  { sub: 'user123', role: 'admin' },
  privateKey,
  { algorithm: 'RS256', expiresIn: '1h' }
);

// Verify with public key (any service)
const decoded = jwt.verify(token, publicKey, {
  algorithms: ['RS256']
});
```

---

## 8. Where to Store JWT on Client

| Storage Method | XSS Vulnerable | CSRF Vulnerable | Notes |
|---|---|---|---|
| **Memory (JS variable)** | No | No | Lost on page refresh — most secure for SPAs |
| **HttpOnly Cookie** | No | Yes | Needs CSRF token; not accessible via JS |
| **localStorage** | Yes | No | Accessible via JS — avoid for auth tokens |
| **sessionStorage** | Yes | No | Tab-scoped, cleared on tab close |

### Recommended: HttpOnly + Secure Cookie

```js
// Server — set cookie
res.cookie('access_token', token, {
  httpOnly: true,       // not accessible via document.cookie
  secure: true,         // HTTPS only
  sameSite: 'Strict',   // CSRF protection
  maxAge: 15 * 60 * 1000  // 15 minutes
});
```

```js
// client automatically sends cookie with requests
// no manual Authorization header needed
fetch('/api/profile', { credentials: 'include' });
```

### If Using Authorization Header (SPA)

```js
// Store in memory — never localStorage
let accessToken = null;

async function login(email, password) {
  const res = await fetch('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password })
  });
  const data = await res.json();
  accessToken = data.accessToken; // store in memory only
}

// Attach to requests
async function apiCall(url) {
  return fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
}
```

---

## 9. Access Tokens & Refresh Tokens

Short-lived access tokens + long-lived refresh tokens is the industry-standard pattern.

```
Access Token:   15 minutes – 1 hour   (used for API access)
Refresh Token:  7 – 30 days           (used only to get new access tokens)
```

### Why Two Tokens?

- Short `exp` on access tokens limits damage if stolen
- Refresh tokens are stored server-side → can be revoked
- User doesn't have to re-login frequently

---

### Refresh Token Flow

```
┌──────────┐                          ┌────────────────┐
│  Client  │                          │     Server     │
└────┬─────┘                          └───────┬────────┘
     │  POST /auth/login                      │
     │  ─────────────────────────────────►    │
     │                                        │
     │  { accessToken, refreshToken }         │
     │  ◄────────────────────────────────     │
     │                                        │
     │  Store:                                │
     │  accessToken  → memory                 │
     │  refreshToken → HttpOnly cookie        │
     │                                        │
     │  ... accessToken expires ...           │
     │                                        │
     │  POST /auth/refresh                    │
     │  Cookie: refreshToken=xxx              │
     │  ─────────────────────────────────►    │
     │                                        │ Validate refresh token
     │                                        │ Issue new access token
     │                                        │ Rotate refresh token
     │  { accessToken: new_token }            │
     │  ◄────────────────────────────────     │
```

---

### Implementing Refresh Tokens

```js
// Login
app.post('/auth/login', async (req, res) => {
  const user = await validateCredentials(req.body);

  const accessToken = jwt.sign(
    { sub: user.id, role: user.role },
    process.env.ACCESS_SECRET,
    { expiresIn: '15m' }
  );

  const refreshToken = jwt.sign(
    { sub: user.id },
    process.env.REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  // Store refresh token in DB
  await db.refreshTokens.create({
    token: refreshToken,
    userId: user.id,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
  });

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });

  res.json({ accessToken });
});

// Refresh
app.post('/auth/refresh', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.status(401).json({ error: 'No refresh token' });

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);

    // Check DB — is this refresh token still valid?
    const stored = await db.refreshTokens.findOne({ token: refreshToken });
    if (!stored) return res.status(401).json({ error: 'Refresh token revoked' });

    // Rotate refresh token
    await db.refreshTokens.delete({ token: refreshToken });

    const newRefreshToken = jwt.sign(
      { sub: decoded.sub },
      process.env.REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    await db.refreshTokens.create({
      token: newRefreshToken,
      userId: decoded.sub,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });

    const newAccessToken = jwt.sign(
      { sub: decoded.sub },
      process.env.ACCESS_SECRET,
      { expiresIn: '15m' }
    );

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// Logout
app.post('/auth/logout', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (refreshToken) {
    await db.refreshTokens.delete({ token: refreshToken });
  }
  res.clearCookie('refreshToken');
  res.json({ message: 'Logged out' });
});
```

### Refresh Token Rotation

Every time a refresh token is used, issue a new one and invalidate the old one.
If a stolen refresh token is used, the legitimate user's next refresh will fail → detect theft.

```
Rotation detects token theft:
1. Attacker steals refresh token
2. Attacker uses it → new token issued, old invalidated
3. Real user tries to refresh → FAIL (token is gone)
4. System detects reuse → revoke ALL tokens for this user
```

---

## 10. JTI — JWT ID

`jti` is a **registered claim** providing a unique identifier for each token — like a serial number.

```json
{
  "sub": "user123",
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "exp": 1710003600
}
```

### Why Use JTI?

- Enables token revocation without a full stateful session
- Prevents replay attacks
- Enables one-time-use tokens
- Enables audit logging per-token

---

### JTI — Blocklist Pattern (Redis)

```js
const { v4: uuidv4 } = require('uuid');

// Issue token with jti
function issueToken(userId, role) {
  return jwt.sign(
    { sub: userId, role, jti: uuidv4() },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

// Verify and check blocklist
async function verifyToken(token) {
  const decoded = jwt.verify(token, process.env.JWT_SECRET, {
    algorithms: ['HS256']
  });

  const isRevoked = await redis.get(`jti:blocklist:${decoded.jti}`);
  if (isRevoked) throw new Error('Token revoked');

  return decoded;
}

// Revoke on logout
async function revokeToken(token) {
  const decoded = jwt.decode(token);
  const ttl = decoded.exp - Math.floor(Date.now() / 1000);

  if (ttl > 0) {
    await redis.set(`jti:blocklist:${decoded.jti}`, '1', 'EX', ttl);
  }
}
```

---

### JTI — One-Time Token (Password Reset, Magic Link)

```js
// Issue
async function issuePasswordResetToken(userId) {
  const jti = uuidv4();

  const token = jwt.sign(
    { sub: userId, purpose: 'password-reset', jti },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );

  // Mark as pending in DB
  await db.passwordResetTokens.create({
    jti,
    userId,
    usedAt: null,
    expiresAt: new Date(Date.now() + 15 * 60 * 1000)
  });

  return token;
}

// Consume (use only once)
async function consumePasswordResetToken(token) {
  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  if (decoded.purpose !== 'password-reset') {
    throw new Error('Wrong token type');
  }

  const stored = await db.passwordResetTokens.findOne({ jti: decoded.jti });

  if (!stored) throw new Error('Token not found');
  if (stored.usedAt) throw new Error('Token already used');

  // Mark as used atomically
  await db.passwordResetTokens.update(
    { jti: decoded.jti },
    { usedAt: new Date() }
  );

  return decoded.sub;
}
```

---

## 11. Token Revocation Strategies

JWT is stateless — once issued, valid until expiry. Here are strategies to revoke before expiry:

### Strategy 1: Short Expiry

```
Access Token: 5-15 minutes
```

No revocation needed for most cases — short window limits damage.

Pros: Simple, truly stateless
Cons: User must refresh frequently

---

### Strategy 2: JTI Blocklist

Store revoked token JTIs in Redis with TTL = remaining token lifetime.

```js
// On logout or password change:
await redis.set(`blocked:${jti}`, '1', 'EX', remainingSeconds);

// On verify:
const blocked = await redis.get(`blocked:${jti}`);
if (blocked) reject();
```

Pros: Precise revocation, minimal storage
Cons: Requires Redis lookup on every request

---

### Strategy 3: User Token Version

Store a `token_version` per user in the database. Include it in the JWT.
Increment the version to invalidate all tokens for a user at once.

```js
// JWT payload
{ sub: 'user123', ver: 5 }

// On verify
const user = await db.users.findById(decoded.sub);
if (decoded.ver !== user.tokenVersion) {
  throw new Error('Token invalidated');
}

// Revoke ALL tokens for user (password change, logout all)
await db.users.update({ id: userId }, { tokenVersion: user.tokenVersion + 1 });
```

Pros: Invalidate all sessions at once, single DB field
Cons: DB lookup on every request

---

### Strategy 4: Short-Lived Access + Revocable Refresh

Revoke the refresh token in the DB. Access tokens expire naturally in minutes.

Pros: Minimal lookups (only on refresh)
Cons: Up to [access token lifetime] window of continued access

---

### Strategy Comparison

| Strategy | Revocation Speed | DB Lookup | Complexity |
|---|---|---|---|
| Short Expiry | Minutes | None | Low |
| JTI Blocklist | Immediate | Every request | Medium |
| Token Version | Immediate | Every request | Medium |
| Revoke Refresh | Minutes | On refresh only | Low |

---

## 12. JWE — JSON Web Encryption

Regular JWTs (JWS) are **signed but not encrypted**. JWE encrypts the payload.

```
JWS: signed   → integrity guaranteed, payload readable
JWE: encrypted → confidentiality guaranteed, payload unreadable
```

### JWE Structure (5 Parts)

```
HEADER . ENCRYPTED_KEY . IV . CIPHERTEXT . AUTH_TAG
```

| Part | Description |
|---|---|
| **Header** | Algorithms used (`alg` for key encryption, `enc` for content encryption) |
| **Encrypted Key** | The Content Encryption Key (CEK), encrypted with recipient's key |
| **IV** | Random Initialization Vector — ensures same input encrypts differently each time |
| **Ciphertext** | The encrypted payload |
| **Auth Tag** | Ensures ciphertext integrity (like a MAC) |

---

### JWE Algorithms

**Key Encryption (`alg`) — how the CEK is wrapped:**

| Algorithm | Type | Notes |
|---|---|---|
| `RSA-OAEP` | Asymmetric | Recommended RSA option |
| `RSA-OAEP-256` | Asymmetric | RSA-OAEP with SHA-256 |
| `RSA1_5` | Asymmetric | Legacy — avoid |
| `A128KW` | Symmetric | AES key wrap |
| `A256KW` | Symmetric | AES 256-bit key wrap |
| `ECDH-ES` | Asymmetric | Elliptic Curve DH |
| `dir` | Symmetric | Direct — CEK is the shared key |

**Content Encryption (`enc`) — how payload is encrypted:**

| Algorithm | Notes |
|---|---|
| `A256GCM` | Recommended — AES-GCM authenticated encryption |
| `A128GCM` | Faster, less secure than A256GCM |
| `A128CBC-HS256` | AES-CBC + HMAC — older, larger tokens |
| `A256CBC-HS512` | AES-CBC + HMAC-SHA512 |

**Best combination:** `RSA-OAEP-256` + `A256GCM`

---

### JWE Encryption Flow

```
1. Generate a random Content Encryption Key (CEK)
2. Encrypt CEK with recipient's public key  → Encrypted Key
3. Generate random IV
4. Encrypt payload using CEK + IV (AES-GCM) → Ciphertext + Auth Tag
5. Assemble all 5 parts
```

### JWE Decryption Flow

```
1. Decode header → get alg and enc
2. Decrypt Encrypted Key using private key  → CEK
3. Decrypt Ciphertext using CEK + IV        → plaintext payload
4. Verify Auth Tag                          → confirm no tampering
```

---

### JWE Code Example (Node.js `jose`)

```bash
npm install jose
```

```js
const { CompactEncrypt, compactDecrypt, generateKeyPair } = require('jose');

// Generate RSA key pair (store securely — do this once)
const { publicKey, privateKey } = await generateKeyPair('RSA-OAEP-256');

// Encrypt
const payload = JSON.stringify({
  sub: 'user123',
  ssn: '123-45-6789',    // safe — payload is encrypted
  salary: 95000
});

const jwe = await new CompactEncrypt(new TextEncoder().encode(payload))
  .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
  .encrypt(publicKey);

// Decrypt
const { plaintext } = await compactDecrypt(jwe, privateKey);
const decoded = JSON.parse(new TextDecoder().decode(plaintext));
console.log(decoded.ssn); // '123-45-6789'
```

---

### Nested JWT — Sign Then Encrypt

For both **integrity** (signature) and **confidentiality** (encryption):

```
Outer layer: JWE (encryption)
Inner layer: JWS (signature)

JWE { payload = JWS { header.payload.signature } }
```

```js
const { SignJWT, CompactEncrypt } = require('jose');

// Step 1: Sign
const signedJWT = await new SignJWT({ sub: 'user123', ssn: '123-45-6789' })
  .setProtectedHeader({ alg: 'RS256' })
  .setIssuedAt()
  .setExpirationTime('1h')
  .sign(signingPrivateKey);

// Step 2: Encrypt the signed JWT
const nestedJWT = await new CompactEncrypt(
  new TextEncoder().encode(signedJWT)
)
  .setProtectedHeader({
    alg: 'RSA-OAEP-256',
    enc: 'A256GCM',
    cty: 'JWT'   // signals inner content is a JWT
  })
  .encrypt(encryptionPublicKey);
```

---

### When to Use JWE

| Scenario | Use JWE? |
|---|---|
| Standard user auth (user ID, role) | No — JWS is fine |
| Token contains SSN, medical records | Yes |
| Token contains financial data | Yes |
| Token passes through untrusted proxy | Yes |
| Token stored in insecure storage | Yes |
| Inter-service in zero-trust architecture | Yes |

---

## 13. JWKS — JSON Web Key Set

JWKS (JSON Web Key Set) is a standard way to publish public keys for token verification.

### Why JWKS?

- Services can automatically discover and rotate verification keys
- No manual key distribution needed
- Supports multiple active keys (for rotation)

### JWKS Endpoint

Auth server exposes a public endpoint:

```
GET https://auth.myapp.com/.well-known/jwks.json
```

Response:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "key-2024-01",
      "alg": "RS256",
      "n": "sB5K...base64url...",
      "e": "AQAB"
    }
  ]
}
```

### Using JWKS in Node.js

```js
const { createRemoteJWKSet, jwtVerify } = require('jose');

const JWKS = createRemoteJWKSet(
  new URL('https://auth.myapp.com/.well-known/jwks.json')
);

async function verifyToken(token) {
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: 'https://auth.myapp.com',
    audience: 'myapp-api'
  });
  return payload;
}
```

The `kid` (Key ID) in the JWT header tells the verifier which key in the JWKS to use.

### Key Rotation with JWKS

```
1. Generate new key pair → add to JWKS (keep old key)
2. Start signing new tokens with new private key
3. Old tokens still verified by old public key (both in JWKS)
4. After old tokens expire → remove old key from JWKS
```

---

## 14. Security Vulnerabilities & Attacks

### Attack 1: `alg: none` Attack

**What:** Attacker sets `alg: "none"` and strips the signature. Vulnerable libraries accept the unsigned token.

```json
// Malicious header
{ "alg": "none", "typ": "JWT" }
// Signature part: empty
```

**Fix:**
```js
// Always explicitly whitelist allowed algorithms
jwt.verify(token, secret, { algorithms: ['HS256'] });  // never omit this
```

---

### Attack 2: Algorithm Confusion (RS256 → HS256)

**What:** Server uses RS256. Attacker gets the public key (it's public), changes `alg` to `HS256`, and signs the token with the public key as the HMAC secret. A naive server verifies using the public key as the HMAC key — succeeds.

**Fix:**
```js
// Hardcode the expected algorithm — never trust the header's alg
jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

---

### Attack 3: Weak Secrets

**What:** Secrets like `"secret"`, `"password"`, `"123456"` can be brute-forced offline once an attacker has a token.

**Fix:**
```bash
# Generate a strong random secret
openssl rand -base64 64
```

```js
// Minimum: 256-bit (32 bytes) for HS256
// Better:  512-bit (64 bytes) for HS512
process.env.JWT_SECRET = "long-random-256-bit-minimum-secret-here"
```

---

### Attack 4: Missing Expiry (`exp`)

**What:** A token without `exp` is valid forever. If stolen, it never expires.

**Fix:**
```js
// Always set expiresIn
jwt.sign(payload, secret, { expiresIn: '15m' });

// On verify, require exp
jwt.verify(token, secret, {
  algorithms: ['HS256'],
  // clockTolerance: 30  // allow 30s clock skew
});
```

---

### Attack 5: Sensitive Data in Payload

**What:** The JWT payload is Base64URL encoded — readable by anyone with the token.
```js
// BAD — never do this
jwt.sign({ sub: userId, password: 'hashed_pass', ssn: '123-45' }, secret);
```

**Fix:** Only store non-sensitive identifiers and roles. Use JWE for sensitive data.

---

### Attack 6: JWT in localStorage

**What:** localStorage is accessible via JavaScript. Any XSS vulnerability → token stolen.

**Fix:** Use `HttpOnly` cookies or in-memory storage for access tokens.

---

### Attack 7: Missing `aud` / `iss` Validation

**What:** A token issued for Service A is used against Service B. If B doesn't validate `aud`, it accepts it.

**Fix:**
```js
jwt.verify(token, secret, {
  algorithms: ['HS256'],
  issuer: 'https://auth.myapp.com',
  audience: 'service-b'
});
```

---

### Attack 8: Replay Attack

**What:** A valid, expired token is replayed after the user has logged out or changed password.

**Fix:** Use `jti` with a blocklist or token version strategy.

---

### Attack 9: JWT Header Injection (kid)

**What:** The `kid` (Key ID) header is used to look up the key. If the server uses `kid` directly in a DB/file query without sanitization:

```json
{ "alg": "HS256", "kid": "' OR '1'='1" }
```

This could cause SQL injection in the key lookup.

**Fix:** Sanitize and validate `kid` values. Use a whitelist of valid key IDs.

---

## 15. Security Best Practices Checklist

### Token Signing
```
[ ] Use HS256 minimum; prefer RS256 or ES256 for distributed systems
[ ] Use strong secrets: 256-bit minimum for HMAC, never guessable strings
[ ] Explicitly specify algorithms in verify() — never trust header's alg
[ ] Never use alg: none
[ ] Rotate signing keys periodically
```

### Token Claims
```
[ ] Always set exp
[ ] Always set iat
[ ] Set iss and validate it on every request
[ ] Set aud and validate it on every request
[ ] Use jti for tokens that need revocation
[ ] Keep payload minimal — only what's needed
[ ] Never store passwords, secrets, or sensitive PII in payload
```

### Token Storage
```
[ ] Use HttpOnly + Secure + SameSite cookies for auth tokens
[ ] If using Bearer: store access token in memory only
[ ] Never store auth tokens in localStorage or sessionStorage
[ ] Store refresh tokens in HttpOnly cookies
```

### Token Lifecycle
```
[ ] Short expiry for access tokens (5-15 minutes)
[ ] Implement refresh token rotation
[ ] Store refresh tokens in DB — revocable
[ ] Revoke all sessions on password change
[ ] Implement logout that actually invalidates tokens
```

### Transport
```
[ ] HTTPS only — never send tokens over HTTP
[ ] Use HSTS headers
[ ] Validate certificate on token endpoint
```

### Key Management
```
[ ] Store secrets in environment variables or secret manager
[ ] Never commit secrets to source control
[ ] Use JWKS for public key distribution
[ ] Implement key rotation without downtime
```

---

## 16. JWT vs Sessions vs OAuth

### JWT vs Sessions

| | JWT | Sessions |
|---|---|---|
| State | Stateless | Stateful (server stores) |
| Storage | Client-side | Server-side |
| Scalability | Horizontal scaling easy | Needs shared session store |
| Revocation | Hard (needs extra work) | Easy (delete session record) |
| Payload size | Larger (in every request) | Small (just session ID) |
| Cross-domain | Works natively | Cookie domain restrictions |
| Mobile-friendly | Yes | Limited |
| Best for | APIs, microservices, mobile | Traditional web apps, monoliths |

### JWT vs OAuth 2.0

These are not competing technologies — they solve different problems:

| | JWT | OAuth 2.0 |
|---|---|---|
| What is it | Token format | Authorization framework |
| Purpose | Represent claims | Delegate access |
| Spec | RFC 7519 | RFC 6749 |
| Relationship | OAuth often uses JWT as the token format |

OAuth 2.0 defines flows (Authorization Code, Client Credentials, etc.) and often uses JWTs as access tokens.

### OpenID Connect (OIDC)

OIDC = OAuth 2.0 + Identity Layer

```
OAuth 2.0:  "Can this app access your Google Drive?"
OIDC:       "Who is this user?" + OAuth 2.0
```

OIDC issues an **ID Token** (a JWT) containing user identity information:
```json
{
  "iss": "https://accounts.google.com",
  "sub": "1234567890",
  "email": "alice@gmail.com",
  "name": "Alice",
  "iat": 1710000000,
  "exp": 1710003600
}
```

---

## 17. JWT in Microservices

### Pattern 1: API Gateway Validation

```
Client → [API Gateway: validate JWT] → Microservice A
                                     → Microservice B
                                     → Microservice C
```

Services trust that the gateway has validated the token. They can read claims from a forwarded header.

```js
// API Gateway
const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
req.headers['x-user-id'] = decoded.sub;
req.headers['x-user-role'] = decoded.role;
// forward to downstream service (no token needed downstream)
```

---

### Pattern 2: Each Service Validates

```
Client → Service A (validates JWT) → Service B (validates JWT)
```

Each service independently validates the JWT using the shared public key or JWKS endpoint.

```js
// Each service has the public key or fetches JWKS
const JWKS = createRemoteJWKSet(new URL('https://auth/.well-known/jwks.json'));

const { payload } = await jwtVerify(token, JWKS, {
  issuer: 'https://auth.myapp.com',
  audience: 'service-b'
});
```

---

### Pattern 3: Service-to-Service JWT

Services issue their own JWTs for inter-service calls (Client Credentials flow):

```js
// Service A calling Service B
const serviceToken = jwt.sign(
  {
    iss: 'service-a',
    aud: 'service-b',
    scope: 'read:users'
  },
  serviceAPrivateKey,
  { algorithm: 'RS256', expiresIn: '5m' }
);

fetch('http://service-b/internal/users', {
  headers: { Authorization: `Bearer ${serviceToken}` }
});
```

---

## 18. Common Error Handling

```js
const jwt = require('jsonwebtoken');

function verifyToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'myapp'
    });
  } catch (err) {
    switch (err.name) {
      case 'TokenExpiredError':
        // token.exp < now
        // → return 401, prompt client to refresh
        throw { status: 401, code: 'TOKEN_EXPIRED', message: 'Token has expired' };

      case 'JsonWebTokenError':
        // malformed token, invalid signature, wrong algorithm
        // → return 401, do not give details (security)
        throw { status: 401, code: 'TOKEN_INVALID', message: 'Invalid token' };

      case 'NotBeforeError':
        // token.nbf > now — token not yet active
        throw { status: 401, code: 'TOKEN_NOT_ACTIVE', message: 'Token not yet valid' };

      default:
        throw { status: 500, code: 'AUTH_ERROR', message: 'Authentication error' };
    }
  }
}
```

---

## 19. Debugging JWT

### Online Tool
Use [jwt.io](https://jwt.io) to decode and inspect any JWT (never paste production tokens).

### Decode in Node.js (without verifying)
```js
const token = 'eyJ...';
const parts = token.split('.');

const header  = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

console.log('Header:', header);
console.log('Payload:', payload);
console.log('Expires:', new Date(payload.exp * 1000).toISOString());
console.log('Issued:', new Date(payload.iat * 1000).toISOString());
```

### Decode in CLI
```bash
# Decode payload (second part)
echo "eyJzdWIiOiJ1c2VyMTIzIn0" | base64 -d
```

### Check Token Expiry
```js
function isExpired(token) {
  const { exp } = jwt.decode(token);
  return Date.now() >= exp * 1000;
}

function secondsUntilExpiry(token) {
  const { exp } = jwt.decode(token);
  return exp - Math.floor(Date.now() / 1000);
}
```

### Common Issues

| Issue | Likely Cause |
|---|---|
| `TokenExpiredError` | Token past `exp` — refresh or re-login |
| `invalid signature` | Wrong secret/key, or token was modified |
| `jwt malformed` | Token is incomplete or not a JWT |
| `invalid algorithm` | Token uses different alg than expected |
| `jwt audience invalid` | `aud` claim doesn't match expected value |
| `jwt issuer invalid` | `iss` claim doesn't match expected value |
| Clock issues | Server clocks out of sync — use `clockTolerance` option |

---

## 20. Quick Reference

### JWT Anatomy

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9          ← Header (Base64URL)
.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIn0  ← Payload (Base64URL)
.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  ← Signature
```

### Token Lifetimes

| Token | Recommended Expiry |
|---|---|
| Access Token | 5 – 15 minutes |
| Refresh Token | 7 – 30 days |
| ID Token (OIDC) | 1 hour |
| Password Reset | 15 minutes |
| Email Verification | 24 hours |
| API Key (machine) | No expiry + rotation |

### Algorithm Decision Tree

```
Single server, simple app?
  └─► HS256

Multiple services, microservices?
  └─► RS256 or ES256

Performance-critical, mobile, IoT?
  └─► ES256

Need to encrypt payload?
  └─► JWE: RSA-OAEP-256 + A256GCM
```

### HTTP Header

```
Authorization: Bearer <token>
```

### Full Payload Example

```json
{
  "iss": "https://auth.myapp.com",
  "sub": "user_abc123",
  "aud": ["myapp-api", "myapp-admin"],
  "exp": 1710003600,
  "nbf": 1710000000,
  "iat": 1710000000,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "role": "admin",
  "permissions": ["read", "write"],
  "tenant": "org_456"
}
```

### Non-Obvious Gotchas

```
1. Base64URL ≠ Base64       → uses - and _ instead of + and =
2. exp is in SECONDS         → not milliseconds (unlike Date.now())
3. Payload is NOT secret     → anyone can decode it
4. Valid ≠ Authorized        → always check claims after verifying signature
5. Logout ≠ Token revoked    → must implement revocation explicitly
6. JWT is not a session      → stateless by nature
7. Bigger payload = bigger header on every request
8. Clock skew matters        → use clockTolerance for distributed systems
9. kid in header is user-controlled → validate before key lookup
10. Never verify with jwt.decode()  → use jwt.verify() always
```
