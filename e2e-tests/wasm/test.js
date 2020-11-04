#!/usr/bin/env node

const { strict: assert } = require('assert');
const { JWK, JWT } = require('jose');

const {
  verifyRsaToken,
  createRsaToken,
  verifyHashToken,
  createHashToken,
  verifyEdToken,
  createEdToken,
} = require('jwt-compact-wasm');

const payload = {
  name: 'John Doe',
  admin: false,
};

function assertRoundTrip({
  algorithm,
  keyGenerator,
  signer,
  verifier,
}) {
  console.log(`Verifying ${algorithm} (JS -> WASM)...`);

  const signingKey = keyGenerator();
  const token = JWT.sign(payload, signingKey, {
    algorithm,
    expiresIn: '1h',
    subject: 'john.doe@example.com',
  });

  const claims = verifier(token, signingKey);
  assert.deepEqual(claims, { sub: 'john.doe@example.com', ...payload });

  console.log(`Verifying ${algorithm} (WASM -> JS)...`);
  const wasmToken = signer(claims, signingKey);
  const wasmClaims = JWT.verify(wasmToken, signingKey);
  assert.equal(typeof wasmClaims.exp, 'number');
  delete wasmClaims.exp;
  assert.deepEqual(wasmClaims, claims);
}

// RSA algorithms.
for (const algorithm of ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']) {
  assertRoundTrip({
    algorithm,
    keyGenerator: () => JWK.generateSync('RSA', 2048),
    signer: (claims, key) => createRsaToken(claims, key.toPEM(true), algorithm),
    verifier: (token, key) => verifyRsaToken(token, key.toPEM(false)),
  });
}

// HMAC-based algorithms.
for (const algorithm of ['HS256', 'HS384', 'HS512']) {
  assertRoundTrip({
    algorithm,
    keyGenerator: () => JWK.generateSync('oct', 160),
    signer: (claims, key) => createHashToken(
      claims,
      Buffer.from(key.k, 'base64'),
      algorithm,
    ),
    verifier: (token, key) => verifyHashToken(token, Buffer.from(key.k, 'base64')),
  });
}

// EdDSA algorithm on the Ed25519 curve.
assertRoundTrip({
  algorithm: 'EdDSA',
  keyGenerator: () => JWK.generateSync('OKP', 'Ed25519'),

  signer: (claims, key) => {
    const privateKeyBytes = Buffer.alloc(64);
    // Create a conventional binary presentation of the key (first, the secret scalar,
    // then the public key).
    Buffer.from(key.d, 'base64').copy(privateKeyBytes, 0);
    Buffer.from(key.x, 'base64').copy(privateKeyBytes, 32);

    return createEdToken(claims, privateKeyBytes);
  },

  verifier: (token, key) => verifyEdToken(token, Buffer.from(key.x, 'base64')),
})
