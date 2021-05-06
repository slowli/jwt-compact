#!/usr/bin/env node

const { strict: assert } = require('assert');
const { SignJWT } = require('jose/jwt/sign');
const { jwtVerify } = require('jose/jwt/verify');
const { fromKeyLike } = require('jose/jwk/from_key_like');
const { generateKeyPair } = require('jose/util/generate_key_pair');
const { generateSecret } = require('jose/util/generate_secret');

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

async function assertRoundTrip({
  algorithm,
  keyGenerator,
  signer,
  verifier,
}) {
  console.log(`Verifying ${algorithm} (JS -> WASM)...`);

  const { privateKey, publicKey } = await keyGenerator();
  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: algorithm })
    .setExpirationTime('1h')
    .setSubject('john.doe@example.com')
    .sign(privateKey);

  const claims = await verifier(token, publicKey);
  assert.deepEqual(claims, { sub: 'john.doe@example.com', ...payload });

  console.log(`Verifying ${algorithm} (WASM -> JS)...`);
  const wasmToken = await signer(claims, privateKey);
  const { payload: wasmClaims } = await jwtVerify(wasmToken, publicKey);
  assert.equal(typeof wasmClaims.exp, 'number');
  delete wasmClaims.exp;
  assert.deepEqual(wasmClaims, claims);
}

async function main() {
  // RSA algorithms.
  for (const algorithm of ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']) {
    await assertRoundTrip({
      algorithm,
      keyGenerator: () => generateKeyPair(algorithm, { modulusLength: 2048 }),
      signer: (claims, key) => createRsaToken(
        claims,
        key.export({ type: 'pkcs8', format: 'pem' }),
        algorithm,
      ),
      verifier: (token, key) => verifyRsaToken(
        token,
        key.export({ type: 'spki', format: 'pem' }),
      ),
    });
  }

  // HMAC-based algorithms.
  for (const algorithm of ['HS256', 'HS384', 'HS512']) {
    await assertRoundTrip({
      algorithm,
      keyGenerator: async () => {
        const secret = await generateSecret(algorithm);
        return { privateKey: secret, publicKey: secret };
      },
      signer: async (claims, key) => createHashToken(
        claims,
        await fromKeyLike(key),
        algorithm,
      ),
      verifier: async (token, key) => verifyHashToken(token, await fromKeyLike(key)),
    });
  }

  // EdDSA algorithm on the Ed25519 curve.
  await assertRoundTrip({
    algorithm: 'EdDSA',
    keyGenerator: () => generateKeyPair('EdDSA', { crv: 'Ed25519' }),

    signer: async (claims, key) => {
      return createEdToken(claims, await fromKeyLike(key));
    },

    verifier: async (token, key) => {
      return verifyEdToken(token, await fromKeyLike(key));
    },
  });
}

main().catch(console.error)
