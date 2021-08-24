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
  verifyEs256kToken,
  createEs256kToken,
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

  const claims = verifier(token, await fromKeyLike(publicKey));
  assert.deepEqual(claims, { sub: 'john.doe@example.com', ...payload });

  console.log(`Verifying ${algorithm} (WASM -> JS)...`);
  const wasmToken = signer(claims, await fromKeyLike(privateKey));
  const { payload: wasmClaims } = await jwtVerify(wasmToken, publicKey);
  assert.equal(typeof wasmClaims.exp, 'number');
  delete wasmClaims.exp;
  assert.deepEqual(wasmClaims, claims);
}

async function iteration() {
  // RSA algorithms.
  for (const algorithm of ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']) {
    await assertRoundTrip({
      algorithm,
      keyGenerator: () => generateKeyPair(algorithm, { modulusLength: 2048 }),
      signer: (claims, jwk) => createRsaToken(claims, jwk, algorithm),
      verifier: verifyRsaToken,
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
      signer: (claims, jwk) => createHashToken(claims, jwk, algorithm),
      verifier: verifyHashToken,
    });
  }

  // EdDSA algorithm on the Ed25519 curve.
  await assertRoundTrip({
    algorithm: 'EdDSA',
    keyGenerator: () => generateKeyPair('EdDSA', { crv: 'Ed25519' }),
    signer: createEdToken,
    verifier: verifyEdToken,
  });

  // ES256K algorithm.
  await assertRoundTrip({
    algorithm: 'ES256K',
    keyGenerator: () => generateKeyPair('ES256K'),
    signer: createEs256kToken,
    verifier: verifyEs256kToken,
  });
}

async function main(iterations = 10) {
  for (let i = 1; i <= iterations; i++) {
    console.log(`Iteration ${i}/${iterations}`);
    await iteration();
  }
}

main().catch(console.error);
