import { randomUUID } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import {
  decodeProtectedHeader,
  jwtVerify,
  SignJWT,
  type JWTPayload,
} from 'jose';
import type {
  AccessTokenIssuer,
  AccessTokenVerifier,
  IssuedAccessToken,
} from '@devtrack-solution/foundation-api/contracts';
import type {
  AuthenticationMethod,
  Principal,
} from '@devtrack-solution/foundation-api/contracts';
import type { SessionReference } from '@devtrack-solution/foundation-api/contracts';
import {
  JWT_AUTH_MAX_TOKEN_LENGTH,
  resolveJwtAuthOptions,
  type JwtAuthOptions,
  type ResolvedJwtAuthOptions,
} from './jwt-auth.options';

/** Falha genérica de emissão. Não carrega causa nem material do token. */
export class JwtAuthIssueError extends Error {
  constructor() {
    super('token_issue_failed');
    this.name = 'JwtAuthIssueError';
  }
}

/** Falha genérica de verificação por causa interna (ex.: relógio indisponível). */
export class JwtAuthUnavailableError extends Error {
  constructor() {
    super('token_verification_unavailable');
    this.name = 'JwtAuthUnavailableError';
  }
}

const MS_PER_SECOND = 1000;

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value);
}

/**
 * Adapter JWT nativo. Implementa AccessTokenIssuer e AccessTokenVerifier.
 * Algoritmos, chaves, emissor e audiência são fixos na configuração; o header
 * do token não escolhe nada além do kid, que deve bater com a política.
 */
export class JwtAccessTokenAdapter
  implements AccessTokenIssuer, AccessTokenVerifier
{
  private readonly policy: ResolvedJwtAuthOptions;
  private readonly maxLifetimeSeconds: number;

  constructor(options: JwtAuthOptions) {
    this.policy = resolveJwtAuthOptions(options);
    this.maxLifetimeSeconds = Math.ceil(this.policy.ttlMs / MS_PER_SECOND);
  }

  async issue(input: {
    readonly principal: Principal;
    readonly session: SessionReference;
    readonly method: AuthenticationMethod;
  }): Promise<IssuedAccessToken> {
    try {
      const nowMs = this.readNow();
      const session = input.session;
      const subjectId = input.principal.subjectId;
      if (
        !isNonEmptyString(subjectId) ||
        !isNonEmptyString(session.id) ||
        !isSafeInteger(session.expiresAt)
      )
        throw new JwtAuthIssueError();

      // exp nunca passa de session.expiresAt. Arredondar para baixo em segundos
      // mantém o expiresAt público menor ou igual ao da sessão.
      const boundMs = Math.min(nowMs + this.policy.ttlMs, session.expiresAt);
      const iat = Math.floor(nowMs / MS_PER_SECOND);
      const exp = Math.floor(boundMs / MS_PER_SECOND);
      if (exp <= iat) throw new JwtAuthIssueError();

      const value = await new SignJWT({ sid: session.id })
        .setProtectedHeader({
          alg: this.policy.signing.alg,
          kid: this.policy.signing.kid,
          typ: 'JWT',
        })
        .setIssuer(this.policy.issuer)
        .setAudience(this.policy.audience)
        .setSubject(subjectId)
        .setJti(randomUUID())
        .setIssuedAt(iat)
        .setNotBefore(iat)
        .setExpirationTime(exp)
        .sign(this.policy.signing.privateKey);

      return { value, expiresAt: exp * MS_PER_SECOND };
    } catch {
      throw new JwtAuthIssueError();
    }
  }

  /**
   * Retorna null para qualquer token inválido, sem detalhar a causa. Lança
   * JwtAuthUnavailableError só para falha interna (ex.: relógio), que deve virar
   * indisponibilidade e não negação.
   */
  async verify(value: string): Promise<{
    readonly subjectId: string;
    readonly sessionId: string;
    readonly expiresAt: number;
  } | null> {
    const nowMs = this.readNow();
    if (!isNonEmptyString(value) || value.length > JWT_AUTH_MAX_TOKEN_LENGTH)
      return null;

    const selected = this.selectKey(value);
    if (selected === null) return null;

    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(value, selected.publicKey, {
        issuer: this.policy.issuer,
        audience: this.policy.audience,
        algorithms: [selected.alg],
        clockTolerance: this.policy.clockToleranceMs / MS_PER_SECOND,
        currentDate: new Date(nowMs),
      }));
    } catch {
      return null;
    }
    return this.claimsOf(payload, nowMs);
  }

  /** Header precisa ter kid conhecido e alg igual ao configurado para ele. */
  private selectKey(
    value: string,
  ): { alg: string; publicKey: KeyObject } | null {
    let header: ReturnType<typeof decodeProtectedHeader>;
    try {
      header = decodeProtectedHeader(value);
    } catch {
      return null;
    }
    if (!isNonEmptyString(header.kid) || !isNonEmptyString(header.alg))
      return null;
    const entry = this.policy.verification.get(header.kid);
    if (entry === undefined || entry.alg !== header.alg) return null;
    return { alg: entry.alg, publicKey: entry.publicKey };
  }

  private claimsOf(
    payload: JWTPayload,
    nowMs: number,
  ): { subjectId: string; sessionId: string; expiresAt: number } | null {
    const { sub, sid, jti, iat, nbf, exp } = payload;
    if (
      !isNonEmptyString(sub) ||
      !isNonEmptyString(sid) ||
      !isNonEmptyString(jti) ||
      !isSafeInteger(iat) ||
      !isSafeInteger(nbf) ||
      !isSafeInteger(exp)
    )
      return null;
    // Emissão no futuro além da tolerância indica relógio ou token adulterado.
    if (iat * MS_PER_SECOND > nowMs + this.policy.clockToleranceMs) return null;
    if (exp - iat > this.maxLifetimeSeconds) return null;
    return { subjectId: sub, sessionId: sid, expiresAt: exp * MS_PER_SECOND };
  }

  private readNow(): number {
    try {
      const now = this.policy.clock.now();
      if (!isSafeInteger(now)) throw new JwtAuthUnavailableError();
      return now;
    } catch {
      throw new JwtAuthUnavailableError();
    }
  }
}
