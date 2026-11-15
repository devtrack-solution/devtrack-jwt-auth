'use strict';
// Boot de conformidade (D8): sobe um contexto Nest com o módulo instalado, emite e verifica um
// token pelas portas exportadas e encerra. Sai com 0 só se o ciclo completo funcionar.
require('reflect-metadata');
const { generateKeyPairSync } = require('node:crypto');
const { Module } = require('@nestjs/common');
const { NestFactory } = require('@nestjs/core');
const { JWT_AUTH_ISSUER, JWT_AUTH_VERIFIER, JwtAuthModule } = require('@devtrack-solution/jwt-auth');

async function main() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const now = Date.now();
  const options = {
    issuer: 'https://conformance.test',
    audience: 'conformance',
    ttlMs: 60_000,
    clockToleranceMs: 1_000,
    algorithms: ['EdDSA'],
    signingKey: { kid: 'k1', alg: 'EdDSA', key: privateKey },
    verificationKeys: [{ kid: 'k1', alg: 'EdDSA', key: publicKey }],
    clock: { now: () => now },
  };
  class BootModule {}
  Module({ imports: [JwtAuthModule.register(options)] })(BootModule);
  const app = await NestFactory.createApplicationContext(BootModule, { logger: false });
  const issued = await app.get(JWT_AUTH_ISSUER, { strict: false }).issue({
    principal: { subjectId: 's1', permissions: [] },
    session: { id: 'sess-1', expiresAt: now + 60_000 },
    method: { kind: 'password' },
  });
  const verified = await app.get(JWT_AUTH_VERIFIER, { strict: false }).verify(issued.value);
  await app.close();
  if (verified === null || verified.subjectId !== 's1' || verified.sessionId !== 'sess-1') process.exit(1);
}

main().then(() => process.exit(0), () => process.exit(1));
