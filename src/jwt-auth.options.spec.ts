import { generateKeyPairSync } from 'node:crypto';
import { JwtAuthConfigError, resolveJwtAuthOptions } from './jwt-auth.options';
import type { JwtAuthOptions } from './jwt-auth.options';

const ed = generateKeyPairSync('ed25519');
const ed2 = generateKeyPairSync('ed25519');
const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const clock = { now: () => 1_700_000_000_000 };

function base(overrides: Partial<JwtAuthOptions> = {}): JwtAuthOptions {
  return {
    issuer: 'https://auth.foundation.test',
    audience: 'foundation-api',
    ttlMs: 15 * 60_000,
    clockToleranceMs: 5_000,
    algorithms: ['EdDSA', 'ES256'],
    signingKey: { kid: 'ed-2026', alg: 'EdDSA', key: ed.privateKey },
    verificationKeys: [{ kid: 'ed-2026', alg: 'EdDSA', key: ed.publicKey }],
    clock,
    ...overrides,
  };
}

describe('resolveJwtAuthOptions', () => {
  it('aceita configuração válida e deriva a parte pública da chave privada', () => {
    const resolved = resolveJwtAuthOptions(
      base({
        verificationKeys: [
          { kid: 'ed-2026', alg: 'EdDSA', key: ed.privateKey },
        ],
      }),
    );
    expect(resolved.signing.kid).toBe('ed-2026');
    expect(resolved.verification.get('ed-2026')?.alg).toBe('EdDSA');
  });

  it('aceita JWK pública e privada como material de chave', () => {
    const privateJwk = ed.privateKey.export({ format: 'jwk' });
    const publicJwk = ed.publicKey.export({ format: 'jwk' });
    expect(() =>
      resolveJwtAuthOptions(
        base({
          signingKey: { kid: 'ed-2026', alg: 'EdDSA', key: privateJwk },
          verificationKeys: [{ kid: 'ed-2026', alg: 'EdDSA', key: publicJwk }],
        }),
      ),
    ).not.toThrow();
  });

  it.each<[string, Partial<JwtAuthOptions>, string]>([
    ['issuer vazio', { issuer: '  ' }, 'issuer'],
    ['audience vazia', { audience: '' }, 'audience'],
    ['ttl zero', { ttlMs: 0 }, 'ttlMs'],
    ['ttl abaixo do mínimo', { ttlMs: 500 }, 'ttlMs'],
    ['ttl acima do máximo', { ttlMs: 25 * 60 * 60 * 1000 }, 'ttlMs'],
    ['ttl fracionário', { ttlMs: 900000.5 }, 'ttlMs'],
    [
      'tolerância acima do limite',
      { clockToleranceMs: 61_000 },
      'clockToleranceMs',
    ],
    ['tolerância negativa', { clockToleranceMs: -1 }, 'clockToleranceMs'],
    [
      'algoritmo proibido na allowlist',
      { algorithms: ['HS256' as 'EdDSA'] },
      'algorithms',
    ],
    ['allowlist vazia', { algorithms: [] }, 'algorithms'],
    ['algoritmo duplicado', { algorithms: ['EdDSA', 'EdDSA'] }, 'algorithms'],
    ['clock inválido', { clock: {} as { now: () => number } }, 'clock'],
    [
      'kid ativo vazio',
      { signingKey: { kid: '', alg: 'EdDSA', key: ed.privateKey } },
      'signingKey.kid',
    ],
    [
      'alg da chave ativa fora da allowlist',
      {
        algorithms: ['ES256'],
        signingKey: { kid: 'ed-2026', alg: 'EdDSA', key: ed.privateKey },
      },
      'signingKey.alg',
    ],
    [
      'chave ativa pública (não privada)',
      { signingKey: { kid: 'ed-2026', alg: 'EdDSA', key: ed.publicKey } },
      'signingKey.key',
    ],
    [
      'chave ativa do tipo errado para o alg',
      { signingKey: { kid: 'ed-2026', alg: 'ES256', key: ed.privateKey } },
      'signingKey.alg',
    ],
    [
      'chave ativa fora do conjunto de verificação',
      {
        verificationKeys: [{ kid: 'ed-old', alg: 'EdDSA', key: ed2.publicKey }],
      },
      'signingKey is missing from verificationKeys',
    ],
    [
      'kid duplicado no conjunto de verificação',
      {
        verificationKeys: [
          { kid: 'ed-2026', alg: 'EdDSA', key: ed.publicKey },
          { kid: 'ed-2026', alg: 'EdDSA', key: ed2.publicKey },
        ],
      },
      'duplicate',
    ],
    [
      'mesmo kid com outra chave pública',
      {
        verificationKeys: [
          { kid: 'ed-2026', alg: 'EdDSA', key: ed2.publicKey },
        ],
      },
      'signingKey is missing from verificationKeys',
    ],
    [
      'chave de verificação ES256 com material Ed25519',
      {
        verificationKeys: [
          { kid: 'ed-2026', alg: 'EdDSA', key: ed.publicKey },
          { kid: 'ec-2026', alg: 'ES256', key: ed.publicKey },
        ],
      },
      'verificationKeys[1].alg',
    ],
    [
      'conjunto de verificação vazio',
      { verificationKeys: [] },
      'verificationKeys',
    ],
    [
      'chave de verificação com alg fora da allowlist',
      {
        algorithms: ['EdDSA'],
        verificationKeys: [
          { kid: 'ed-2026', alg: 'EdDSA', key: ed.publicKey },
          { kid: 'ec-2026', alg: 'ES256', key: ec.publicKey },
        ],
      },
      'verificationKeys[1].alg',
    ],
    [
      'chave de verificação com kid inválido',
      {
        verificationKeys: [
          { kid: 'ed-2026', alg: 'EdDSA', key: ed.publicKey },
          { kid: 'bad kid!', alg: 'EdDSA', key: ed2.publicKey },
        ],
      },
      'verificationKeys[1].kid',
    ],
  ])('rejeita %s', (_name, overrides, field) => {
    let thrown: unknown;
    try {
      resolveJwtAuthOptions(base(overrides));
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(JwtAuthConfigError);
    expect((thrown as Error).message).toContain(field);
  });

  it('não vaza material de chave na mensagem de erro', () => {
    const pem = ed.privateKey.export({
      type: 'pkcs8',
      format: 'pem',
    }) as string;
    try {
      resolveJwtAuthOptions(
        base({
          signingKey: { kid: 'ed-2026', alg: 'ES256', key: ed.privateKey },
        }),
      );
      throw new Error('expected failure');
    } catch (error) {
      expect((error as Error).message).not.toContain(pem.split('\n')[1] ?? '');
      expect((error as Error).message).not.toMatch(/BEGIN|PRIVATE/);
    }
  });
});
