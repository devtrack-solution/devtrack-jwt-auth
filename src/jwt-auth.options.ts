import {
  createPrivateKey,
  createPublicKey,
  KeyObject,
  type JsonWebKey,
} from 'node:crypto';
import type { Clock } from '@devtrack/foundation-api/contracts';

/** Algoritmos assimétricos suportados. Qualquer outro é rejeitado na configuração. */
export const JWT_AUTH_ALGORITHMS = ['EdDSA', 'ES256'] as const;
export type JwtAuthAlgorithm = (typeof JWT_AUTH_ALGORITHMS)[number];

/** Limites de política. Valores fora deles impedem o boot. */
export const JWT_AUTH_MAX_CLOCK_TOLERANCE_MS = 60_000;
export const JWT_AUTH_MAX_TTL_MS = 24 * 60 * 60 * 1000;
export const JWT_AUTH_MIN_TTL_MS = 1000;
/** Tokens acima deste tamanho são rejeitados antes de qualquer decodificação. */
export const JWT_AUTH_MAX_TOKEN_LENGTH = 4096;

/** Material de chave: KeyObject ou JWK. Nunca um segredo simétrico. */
export type JwtAuthKeyMaterial = KeyObject | JsonWebKey;

export interface JwtAuthSigningKey {
  readonly kid: string;
  readonly alg: JwtAuthAlgorithm;
  /** Chave privada. JWK privada (com `d`) também é aceita. */
  readonly key: JwtAuthKeyMaterial;
}

export interface JwtAuthVerificationKey {
  readonly kid: string;
  readonly alg: JwtAuthAlgorithm;
  /** Chave pública ou privada (a pública é derivada). */
  readonly key: JwtAuthKeyMaterial;
}

export interface JwtAuthOptions {
  readonly issuer: string;
  readonly audience: string;
  /** TTL máximo do token em milissegundos. */
  readonly ttlMs: number;
  /** Tolerância de relógio para exp/nbf/iat, em milissegundos (0 a 60000). */
  readonly clockToleranceMs: number;
  /** Allowlist explícita. O verificador aceita somente estes algoritmos. */
  readonly algorithms: readonly JwtAuthAlgorithm[];
  /** Chave ativa usada para assinar novos tokens. */
  readonly signingKey: JwtAuthSigningKey;
  /** Conjunto de verificação por kid. Deve conter a chave ativa. */
  readonly verificationKeys: readonly JwtAuthVerificationKey[];
  readonly clock: Clock;
}

/** Erro de configuração. A mensagem cita o campo, nunca material de chave. */
export class JwtAuthConfigError extends Error {
  constructor(field: string) {
    super(`Invalid JWT auth configuration: ${field}`);
    this.name = 'JwtAuthConfigError';
  }
}

/** Configuração validada e normalizada. Só existe por meio de resolveJwtAuthOptions. */
export interface ResolvedJwtAuthOptions {
  readonly issuer: string;
  readonly audience: string;
  readonly ttlMs: number;
  readonly clockToleranceMs: number;
  readonly signing: {
    readonly kid: string;
    readonly alg: JwtAuthAlgorithm;
    readonly privateKey: KeyObject;
  };
  readonly verification: ReadonlyMap<
    string,
    { readonly alg: JwtAuthAlgorithm; readonly publicKey: KeyObject }
  >;
  readonly clock: Clock;
}

const KID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function nonEmpty(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function isAlgorithm(value: unknown): value is JwtAuthAlgorithm {
  return (JWT_AUTH_ALGORITHMS as readonly unknown[]).includes(value);
}

function toKeyObject(material: unknown, field: string): KeyObject {
  if (material instanceof KeyObject) return material;
  if (typeof material === 'object' && material !== null && 'kty' in material) {
    try {
      const jwk = material as JsonWebKey;
      return 'd' in jwk
        ? createPrivateKey({ key: jwk, format: 'jwk' })
        : createPublicKey({ key: jwk, format: 'jwk' });
    } catch {
      throw new JwtAuthConfigError(`${field}.key`);
    }
  }
  throw new JwtAuthConfigError(`${field}.key`);
}

/** Verifica que a chave combina com o algoritmo declarado. */
function assertKeyMatchesAlgorithm(
  key: KeyObject,
  alg: JwtAuthAlgorithm,
  field: string,
): void {
  const details = key.asymmetricKeyDetails;
  const matches =
    alg === 'EdDSA'
      ? key.asymmetricKeyType === 'ed25519'
      : key.asymmetricKeyType === 'ec' && details?.namedCurve === 'prime256v1';
  if (!matches) throw new JwtAuthConfigError(`${field}.alg`);
}

function publicKeyOf(key: KeyObject): KeyObject {
  return key.type === 'private' ? createPublicKey(key) : key;
}

/**
 * Valida a política inteira antes de qualquer uso. Falha com JwtAuthConfigError
 * que cita apenas o campo afetado. Nunca inclui chave, token ou PEM na mensagem.
 */
export function resolveJwtAuthOptions(
  options: JwtAuthOptions,
): ResolvedJwtAuthOptions {
  if (typeof options !== 'object' || options === null)
    throw new JwtAuthConfigError('options');
  if (!nonEmpty(options.issuer)) throw new JwtAuthConfigError('issuer');
  if (!nonEmpty(options.audience)) throw new JwtAuthConfigError('audience');

  if (
    !Number.isSafeInteger(options.ttlMs) ||
    options.ttlMs < JWT_AUTH_MIN_TTL_MS ||
    options.ttlMs > JWT_AUTH_MAX_TTL_MS
  )
    throw new JwtAuthConfigError('ttlMs');

  if (
    !Number.isSafeInteger(options.clockToleranceMs) ||
    options.clockToleranceMs < 0 ||
    options.clockToleranceMs > JWT_AUTH_MAX_CLOCK_TOLERANCE_MS
  )
    throw new JwtAuthConfigError('clockToleranceMs');

  if (!Array.isArray(options.algorithms) || options.algorithms.length === 0)
    throw new JwtAuthConfigError('algorithms');
  const allowed = new Set<string>();
  for (const alg of options.algorithms) {
    if (!isAlgorithm(alg) || allowed.has(alg))
      throw new JwtAuthConfigError('algorithms');
    allowed.add(alg);
  }

  if (typeof options.clock?.now !== 'function')
    throw new JwtAuthConfigError('clock');

  const signing = options.signingKey;
  if (
    typeof signing !== 'object' ||
    signing === null ||
    !nonEmpty(signing.kid) ||
    !KID_PATTERN.test(signing.kid)
  )
    throw new JwtAuthConfigError('signingKey.kid');
  if (!isAlgorithm(signing.alg) || !allowed.has(signing.alg))
    throw new JwtAuthConfigError('signingKey.alg');
  const privateKey = toKeyObject(signing.key, 'signingKey');
  if (privateKey.type !== 'private')
    throw new JwtAuthConfigError('signingKey.key');
  assertKeyMatchesAlgorithm(privateKey, signing.alg, 'signingKey');

  const rawVerificationKeys: unknown = options.verificationKeys;
  if (!Array.isArray(rawVerificationKeys) || rawVerificationKeys.length === 0)
    throw new JwtAuthConfigError('verificationKeys');
  const verificationKeys =
    rawVerificationKeys as readonly JwtAuthVerificationKey[];
  const verification = new Map<
    string,
    { alg: JwtAuthAlgorithm; publicKey: KeyObject }
  >();
  verificationKeys.forEach((entry, index) => {
    const field = `verificationKeys[${index}]`;
    if (
      typeof entry !== 'object' ||
      entry === null ||
      !nonEmpty(entry.kid) ||
      !KID_PATTERN.test(entry.kid)
    )
      throw new JwtAuthConfigError(`${field}.kid`);
    if (verification.has(entry.kid))
      throw new JwtAuthConfigError(`${field}.kid (duplicate)`);
    if (!isAlgorithm(entry.alg) || !allowed.has(entry.alg))
      throw new JwtAuthConfigError(`${field}.alg`);
    const key = toKeyObject(entry.key, field);
    if (key.type === 'secret') throw new JwtAuthConfigError(`${field}.key`);
    assertKeyMatchesAlgorithm(key, entry.alg, field);
    verification.set(entry.kid, {
      alg: entry.alg,
      publicKey: publicKeyOf(key),
    });
  });

  // A chave ativa deve estar no conjunto de verificação, com o mesmo alg e a
  // mesma parte pública. Sem isso, tokens recém-emitidos não verificariam.
  const active = verification.get(signing.kid);
  if (
    active === undefined ||
    active.alg !== signing.alg ||
    !active.publicKey
      .export({ type: 'spki', format: 'der' })
      .equals(publicKeyOf(privateKey).export({ type: 'spki', format: 'der' }))
  )
    throw new JwtAuthConfigError('signingKey is missing from verificationKeys');

  return {
    issuer: options.issuer,
    audience: options.audience,
    ttlMs: options.ttlMs,
    clockToleranceMs: options.clockToleranceMs,
    signing: { kid: signing.kid, alg: signing.alg, privateKey },
    verification,
    clock: options.clock,
  };
}
