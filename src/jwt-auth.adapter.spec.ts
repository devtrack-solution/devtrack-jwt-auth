import {
  createSecretKey,
  generateKeyPairSync,
  randomUUID,
  type KeyObject,
} from 'node:crypto';
import { decodeJwt, decodeProtectedHeader, SignJWT } from 'jose';
import { JwtAccessTokenAdapter } from './jwt-auth.adapter';
import type {
  JwtAuthOptions,
  JwtAuthVerificationKey,
} from './jwt-auth.options';

const ISSUER = 'https://auth.foundation.test';
const AUDIENCE = 'foundation-api';
const NOW = 1_700_000_000_000;
const TTL_MS = 15 * 60_000;
const TOLERANCE_MS = 5_000;

const ed = generateKeyPairSync('ed25519');
const ed2 = generateKeyPairSync('ed25519');
const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });

interface MutableClock {
  now(): number;
  advance(ms: number): void;
  broken: boolean;
}

function clockAt(initial: number): MutableClock {
  let current = initial;
  const clock: MutableClock = {
    now: () => {
      if (clock.broken) throw new Error('clock down: secret-internal');
      return current;
    },
    advance: (ms: number) => {
      current += ms;
    },
    broken: false,
  };
  return clock;
}

function options(
  clock: MutableClock,
  overrides: Partial<JwtAuthOptions> = {},
): JwtAuthOptions {
  return {
    issuer: ISSUER,
    audience: AUDIENCE,
    ttlMs: TTL_MS,
    clockToleranceMs: TOLERANCE_MS,
    algorithms: ['EdDSA', 'ES256'],
    signingKey: { kid: 'ed-2026', alg: 'EdDSA', key: ed.privateKey },
    verificationKeys: [{ kid: 'ed-2026', alg: 'EdDSA', key: ed.publicKey }],
    clock,
    ...overrides,
  };
}

const session = (now: number, expiresIn = 60 * 60_000) => ({
  id: 'sess-1',
  expiresAt: now + expiresIn,
});
const principal = { subjectId: 'user-1', permissions: ['things:read'] };

/** Claims válidos no instante `now`. `undefined` remove a claim. */
function claimsAt(now: number, extra: Record<string, unknown> = {}) {
  const iat = Math.floor(now / 1000);
  return {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: 'user-1',
    sid: 'sess-1',
    jti: randomUUID(),
    iat,
    nbf: iat,
    exp: iat + TTL_MS / 1000,
    ...extra,
  };
}

async function signWith(
  claims: Record<string, unknown>,
  key: KeyObject,
  header: { alg: string; kid?: string },
): Promise<string> {
  return new SignJWT(claims).setProtectedHeader(header).sign(key);
}

const b64 = (value: string) => Buffer.from(value).toString('base64url');

function withSignature(token: string, index: number): string {
  const [head = '', body = '', sig = ''] = token.split('.');
  const flipped = sig[index] === 'A' ? 'B' : 'A';
  const mutated = sig.slice(0, index) + flipped + sig.slice(index + 1);
  return `${head}.${body}.${mutated}`;
}

describe('JwtAccessTokenAdapter', () => {
  let clock: MutableClock;

  beforeEach(() => {
    clock = clockAt(NOW);
  });

  describe('ida e volta', () => {
    it('emite e verifica devolvendo subject, sessão e expiração em milissegundos', async () => {
      const adapter = new JwtAccessTokenAdapter(options(clock));
      const issued = await adapter.issue({
        principal,
        session: session(NOW),
        method: { kind: 'password' },
      });

      const verified = await adapter.verify(issued.value);
      expect(verified).toEqual({
        subjectId: 'user-1',
        sessionId: 'sess-1',
        expiresAt: issued.expiresAt,
      });
      expect(issued.expiresAt % 1000).toBe(0);
      expect(issued.expiresAt).toBe(NOW + TTL_MS);
    });

    it('nunca devolve expiração maior que a da sessão, mesmo com arredondamento', async () => {
      const adapter = new JwtAccessTokenAdapter(options(clock));
      const sessionEnd = NOW + 90_500;
      const issued = await adapter.issue({
        principal,
        session: { id: 'sess-1', expiresAt: sessionEnd },
        method: { kind: 'password' },
      });
      expect(issued.expiresAt).toBeLessThanOrEqual(sessionEnd);
      expect(issued.expiresAt).toBe(90_000 + Math.floor(NOW / 1000) * 1000);
      expect(await adapter.verify(issued.value)).toMatchObject({
        expiresAt: issued.expiresAt,
      });
    });

    it('contém somente as claims permitidas, sem permissões, tenant, email ou método', async () => {
      const adapter = new JwtAccessTokenAdapter(options(clock));
      const issued = await adapter.issue({
        principal: { ...principal, tenantId: 'tenant-a' },
        session: session(NOW),
        method: { kind: 'federated', providerId: 'google' },
      });
      expect(Object.keys(decodeJwt(issued.value)).sort()).toEqual(
        ['aud', 'exp', 'iat', 'iss', 'jti', 'nbf', 'sid', 'sub'].sort(),
      );
      expect(decodeProtectedHeader(issued.value)).toMatchObject({
        alg: 'EdDSA',
        kid: 'ed-2026',
      });
    });

    it('gera jti distinto em cada emissão', async () => {
      const adapter = new JwtAccessTokenAdapter(options(clock));
      const a = await adapter.issue({
        principal,
        session: session(NOW),
        method: { kind: 'password' },
      });
      const b = await adapter.issue({
        principal,
        session: session(NOW),
        method: { kind: 'password' },
      });
      expect(decodeJwt(a.value).jti).not.toBe(decodeJwt(b.value).jti);
    });

    it('recusa emitir quando a sessão já expirou', async () => {
      const adapter = new JwtAccessTokenAdapter(options(clock));
      await expect(
        adapter.issue({
          principal,
          session: { id: 'sess-1', expiresAt: NOW },
          method: { kind: 'password' },
        }),
      ).rejects.toThrow('token_issue_failed');
    });

    it('falha de relógio na emissão lança erro genérico sem causa', async () => {
      const adapter = new JwtAccessTokenAdapter(options(clock));
      clock.broken = true;
      const failure = adapter.issue({
        principal,
        session: session(NOW),
        method: { kind: 'password' },
      });
      await expect(failure).rejects.toThrow('token_issue_failed');
      await failure.catch((error: unknown) =>
        expect(String(error)).not.toMatch(/secret-internal/),
      );
    });
  });

  describe('tokens inválidos devolvem null', () => {
    const cases: [string, () => Promise<string>][] = [
      [
        'assinatura adulterada',
        async () => withSignature(await validToken(), 10),
      ],
      [
        'payload adulterado',
        async () => {
          const [head, , sig] = (await validToken()).split('.');
          const forged = b64(
            JSON.stringify({ ...claimsAt(NOW), sub: 'admin' }),
          );
          return `${head}.${forged}.${sig}`;
        },
      ],
      ['malformado', () => Promise.resolve('not-a-jwt')],
      ['partes insuficientes', () => Promise.resolve('a.b')],
      ['cinco partes', async () => `${await validToken()}.extra`],
      ['vazio', () => Promise.resolve('')],
      [
        'acima do tamanho máximo',
        async () => `${await validToken()}${'a'.repeat(5000)}`,
      ],
      [
        'alg none',
        () =>
          Promise.resolve(
            `${b64(JSON.stringify({ alg: 'none', kid: 'ed-2026' }))}.${b64(JSON.stringify(claimsAt(NOW)))}.`,
          ),
      ],
      [
        'HS256 com chave pública como segredo',
        async () =>
          signWith(
            claimsAt(NOW),
            createSecretKey(
              Buffer.from(
                ed.publicKey.export({ type: 'spki', format: 'pem' }) as string,
              ),
            ),
            { alg: 'HS256', kid: 'ed-2026' },
          ),
      ],
      [
        'alg fora da allowlist com kid conhecido',
        async () =>
          signWith(claimsAt(NOW), rsa.privateKey, {
            alg: 'RS256',
            kid: 'ed-2026',
          }),
      ],
      [
        'alg diferente do configurado para o kid',
        async () =>
          signWith(claimsAt(NOW), ec.privateKey, {
            alg: 'ES256',
            kid: 'ed-2026',
          }),
      ],
      [
        'kid desconhecido',
        async () =>
          signWith(claimsAt(NOW), ed.privateKey, {
            alg: 'EdDSA',
            kid: 'ed-9999',
          }),
      ],
      [
        'kid ausente',
        async () => signWith(claimsAt(NOW), ed.privateKey, { alg: 'EdDSA' }),
      ],
      [
        'assinado por outra chave com o mesmo kid',
        async () =>
          signWith(claimsAt(NOW), ed2.privateKey, {
            alg: 'EdDSA',
            kid: 'ed-2026',
          }),
      ],
      [
        'issuer errado',
        async () =>
          signWith(claimsAt(NOW, { iss: 'https://evil.test' }), ed.privateKey, {
            alg: 'EdDSA',
            kid: 'ed-2026',
          }),
      ],
      [
        'audiência errada',
        async () =>
          signWith(claimsAt(NOW, { aud: 'other-api' }), ed.privateKey, {
            alg: 'EdDSA',
            kid: 'ed-2026',
          }),
      ],
      [
        'expirado além da tolerância',
        async () =>
          signWith(
            claimsAt(NOW, {
              exp: Math.floor(NOW / 1000) - TOLERANCE_MS / 1000 - 1,
            }),
            ed.privateKey,
            { alg: 'EdDSA', kid: 'ed-2026' },
          ),
      ],
      [
        'nbf no futuro além da tolerância',
        async () => {
          const iat = Math.floor(NOW / 1000);
          return signWith(
            claimsAt(NOW, { nbf: iat + 60, exp: iat + 900 }),
            ed.privateKey,
            { alg: 'EdDSA', kid: 'ed-2026' },
          );
        },
      ],
      [
        'iat no futuro além da tolerância',
        async () => {
          const iat = Math.floor(NOW / 1000) + 60;
          return signWith(
            claimsAt(NOW, { iat, nbf: iat, exp: iat + 900 }),
            ed.privateKey,
            { alg: 'EdDSA', kid: 'ed-2026' },
          );
        },
      ],
      [
        'sem sub',
        async () =>
          signWith(claimsAt(NOW, { sub: undefined }), ed.privateKey, {
            alg: 'EdDSA',
            kid: 'ed-2026',
          }),
      ],
      [
        'sem sid',
        async () =>
          signWith(claimsAt(NOW, { sid: undefined }), ed.privateKey, {
            alg: 'EdDSA',
            kid: 'ed-2026',
          }),
      ],
      [
        'sem jti',
        async () =>
          signWith(claimsAt(NOW, { jti: undefined }), ed.privateKey, {
            alg: 'EdDSA',
            kid: 'ed-2026',
          }),
      ],
      [
        'sub vazio',
        async () =>
          signWith(claimsAt(NOW, { sub: '' }), ed.privateKey, {
            alg: 'EdDSA',
            kid: 'ed-2026',
          }),
      ],
      [
        'tempo de vida acima do máximo',
        async () => {
          const iat = Math.floor(NOW / 1000);
          return signWith(
            claimsAt(NOW, { exp: iat + TTL_MS / 1000 + 1 }),
            ed.privateKey,
            { alg: 'EdDSA', kid: 'ed-2026' },
          );
        },
      ],
    ];

    it.each(cases)('%s', async (_name, build) => {
      const adapter = new JwtAccessTokenAdapter(options(clock));
      await expect(adapter.verify(await build())).resolves.toBeNull();
    });

    async function validToken(): Promise<string> {
      return signWith(claimsAt(NOW), ed.privateKey, {
        alg: 'EdDSA',
        kid: 'ed-2026',
      });
    }

    it('token expirado é rejeitado mesmo com a tolerância configurada', async () => {
      const adapter = new JwtAccessTokenAdapter(options(clock));
      const issued = await adapter.issue({
        principal,
        session: session(NOW),
        method: { kind: 'password' },
      });
      clock.advance(TTL_MS + TOLERANCE_MS + 1000);
      await expect(adapter.verify(issued.value)).resolves.toBeNull();
    });

    it('aceita token expirado dentro da tolerância de relógio', async () => {
      const adapter = new JwtAccessTokenAdapter(options(clock));
      const issued = await adapter.issue({
        principal,
        session: session(NOW),
        method: { kind: 'password' },
      });
      clock.advance(TTL_MS + TOLERANCE_MS - 1000);
      await expect(adapter.verify(issued.value)).resolves.not.toBeNull();
    });

    it('aceita nbf dentro da tolerância de relógio', async () => {
      const adapter = new JwtAccessTokenAdapter(options(clock));
      const iat = Math.floor(NOW / 1000);
      const token = await signWith(
        claimsAt(NOW, { nbf: iat + 3, exp: iat + 900 }),
        ed.privateKey,
        { alg: 'EdDSA', kid: 'ed-2026' },
      );
      await expect(adapter.verify(token)).resolves.not.toBeNull();
    });

    it('falha interna do relógio na verificação lança erro genérico, não null', async () => {
      const adapter = new JwtAccessTokenAdapter(options(clock));
      const issued = await adapter.issue({
        principal,
        session: session(NOW),
        method: { kind: 'password' },
      });
      clock.broken = true;
      const failure = adapter.verify(issued.value);
      await expect(failure).rejects.toThrow('token_verification_unavailable');
      await failure.catch((error: unknown) =>
        expect(String(error)).not.toContain(issued.value.slice(0, 20)),
      );
    });
  });

  describe('rotação de chaves', () => {
    const oldKey = (): JwtAuthVerificationKey => ({
      kid: 'ed-old',
      alg: 'EdDSA',
      key: ed.publicKey,
    });

    it('token assinado com chave antiga ainda listada verifica', async () => {
      const issuerOld = new JwtAccessTokenAdapter(
        options(clock, {
          signingKey: { kid: 'ed-old', alg: 'EdDSA', key: ed.privateKey },
          verificationKeys: [oldKey()],
        }),
      );
      const issued = await issuerOld.issue({
        principal,
        session: session(NOW),
        method: { kind: 'password' },
      });

      const rotated = new JwtAccessTokenAdapter(
        options(clock, {
          signingKey: { kid: 'ed-new', alg: 'EdDSA', key: ed2.privateKey },
          verificationKeys: [
            oldKey(),
            { kid: 'ed-new', alg: 'EdDSA', key: ed2.publicKey },
          ],
        }),
      );
      await expect(rotated.verify(issued.value)).resolves.toMatchObject({
        subjectId: 'user-1',
      });

      const reissued = await rotated.issue({
        principal,
        session: session(NOW),
        method: { kind: 'password' },
      });
      expect(decodeProtectedHeader(reissued.value).kid).toBe('ed-new');
    });

    it('chave removida do conjunto deixa de verificar tokens antigos', async () => {
      const issuerOld = new JwtAccessTokenAdapter(
        options(clock, {
          signingKey: { kid: 'ed-old', alg: 'EdDSA', key: ed.privateKey },
          verificationKeys: [oldKey()],
        }),
      );
      const issued = await issuerOld.issue({
        principal,
        session: session(NOW),
        method: { kind: 'password' },
      });

      const afterRemoval = new JwtAccessTokenAdapter(
        options(clock, {
          signingKey: { kid: 'ed-new', alg: 'EdDSA', key: ed2.privateKey },
          verificationKeys: [
            { kid: 'ed-new', alg: 'EdDSA', key: ed2.publicKey },
          ],
        }),
      );
      await expect(afterRemoval.verify(issued.value)).resolves.toBeNull();
    });
  });
});
