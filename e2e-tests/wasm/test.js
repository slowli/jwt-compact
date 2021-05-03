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
      signer: (claims, key) => createHashToken(
        claims,
        key.export({ format: 'buffer' }),
        algorithm,
      ),
      verifier: (token, key) => verifyHashToken(token, key.export({ format: 'buffer' })),
    });
  }

  // EdDSA algorithm on the Ed25519 curve.
  await assertRoundTrip({
    algorithm: 'EdDSA',
    keyGenerator: () => generateKeyPair('EdDSA', { crv: 'Ed25519' }),

    signer: async (claims, key) => {
      const jwk = await fromKeyLike(key);
      const privateKeyBytes = Buffer.alloc(64);
      // Create a conventional binary presentation of the key (first, the secret scalar,
      // then the public key).
      Buffer.from(jwk.d, 'base64').copy(privateKeyBytes, 0);
      Buffer.from(jwk.x, 'base64').copy(privateKeyBytes, 32);

      return createEdToken(claims, privateKeyBytes);
    },

    verifier: async (token, key) => {
      const jwk = await fromKeyLike(key);
      return verifyEdToken(token, Buffer.from(jwk.x, 'base64'));
    },
  });
}

main().catch(console.error)
