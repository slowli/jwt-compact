#!/usr/bin/env node

const { strict: assert } = require('assert');
const { JWK, JWT } = require('jose');

const { verifyRsaToken, verifyHashToken, verifyEdToken } = require('jwt-compact-wasm');

const payload = {
  name: 'John Doe',
  admin: false
};

// RSA algorithms.
for (const algorithm of ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']) {
  console.log(`Verifying ${algorithm}...`);

  const privateKey = JWK.generateSync('RSA', 2048);
  const publicKey = privateKey.toPEM();

  const token = JWT.sign(payload, privateKey, {
    algorithm,
    expiresIn: '1h',
    subject: 'john.doe@example.com'
  });

  const claims = verifyRsaToken(token, publicKey);
  assert.deepEqual(claims, { sub: 'john.doe@example.com', ...payload });
}

// HMAC-based algorithms.
for (const algorithm of ['HS256', 'HS384', 'HS512']) {
  console.log(`Verifying ${algorithm}...`);

  const secretKey = JWK.generateSync('oct', 160);
  const token = JWT.sign(payload, secretKey, {
    algorithm,
    expiresIn: '1h',
    subject: 'john.doe@example.com'
  });

  const claims = verifyHashToken(token, Buffer.from(secretKey.k, 'base64'));
  assert.deepEqual(claims, { sub: 'john.doe@example.com', ...payload });
}

// Ed25519 algorithm.
console.log('Verifying Ed25519...');
const privateKey = JWK.generateSync('OKP', 'Ed25519');
const token = JWT.sign(payload, privateKey, {
  algorithm: 'EdDSA',
  expiresIn: '1h',
  subject: 'john.doe@example.com'
});

const claims = verifyEdToken(token, Buffer.from(privateKey.x, 'base64'));
assert.deepEqual(claims, { sub: 'john.doe@example.com', ...payload });
