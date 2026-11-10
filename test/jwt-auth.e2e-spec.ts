/* eslint-disable @typescript-eslint/require-await -- dublês de porta assíncronos sem await */
import {
  Body,
  Controller,
  Get,
  Inject,
  Module,
  Post,
  UseGuards,
  type INestApplication,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { createSecretKey, generateKeyPairSync } from 'node:crypto';
import { decodeJwt, SignJWT } from 'jose';
import request from 'supertest';
import { App } from 'supertest/types';
import {
  AuthenticationGuard,
  FoundationCoreModule,
  RequirePermissions,
} from '@devtrack/foundation-api/nest';
import { AUTHENTICATION_SERVICE } from '@devtrack/foundation-api/contracts';
import type { AuthenticationService } from '@devtrack/foundation-api/contracts';
import { JWT_AUTH_ISSUER, JWT_AUTH_VERIFIER, JwtAuthModule } from '../src';
import type { JwtAuthOptions } from '../src';

const ISSUER = 'https://auth.foundation.test';
const AUDIENCE = 'foundation-api';
const START = 1_700_000_000_000;
const SESSION_MS = 60 * 60_000;
const TTL_MS = 15 * 60_000;

const signing = generateKeyPairSync('ed25519');
const intruder = generateKeyPairSync('ed25519');

/** Relógio compartilhado pelo adapter JWT e pelas portas do Nest. */
const clock = {
  current: START,
  failing: false,
  now: (): number => {
    if (clock.failing) throw new Error('clock down: postgres://secret');
    return clock.current;
  },
};

interface SessionRow {
  id: string;
  subjectId: string;
  state: 'pending' | 'active' | 'revoked' | 'expired';
  expiresAt: number;
}
const sessions = new Map<string, SessionRow>();
let sessionCounter = 0;

const sessionPort = {
  createPending: async (principal: { subjectId: string }) => {
    sessionCounter += 1;
    const row: SessionRow = {
      id: `sess-${sessionCounter}`,
      subjectId: principal.subjectId,
      state: 'pending',
      expiresAt: clock.now() + SESSION_MS,
    };
    sessions.set(row.id, row);
    return { id: row.id, expiresAt: row.expiresAt };
  },
  activate: async (id: string) => {
    const row = sessions.get(id);
    if (row) row.state = 'active';
  },
  revoke: async (id: string) => {
    const row = sessions.get(id);
    if (row) row.state = 'revoked';
  },
  find: async (id: string) => sessions.get(id) ?? null,
};

const identityPort = {
  bySubject: async (subjectId: string) =>
    subjectId === 'user-1'
      ? {
          subjectId,
          tenantId: 'tenant-a',
          permissions: ['things:read'],
        }
      : null,
  byExternalIdentity: async () => null,
};

const passwordPort = {
  verify: async ({
    username,
    password,
  }: {
    username: string;
    password: string;
  }) =>
    username === 'alice' && password === 'correct-horse'
      ? { subjectId: 'user-1' }
      : null,
};

@Module({
  providers: [
    { provide: 'E2E_SESSIONS', useValue: sessionPort },
    { provide: 'E2E_IDENTITIES', useValue: identityPort },
    { provide: 'E2E_PASSWORD', useValue: passwordPort },
    { provide: 'E2E_CLOCK', useValue: clock },
  ],
  exports: ['E2E_SESSIONS', 'E2E_IDENTITIES', 'E2E_PASSWORD', 'E2E_CLOCK'],
})
class PortsModule {}

const jwtOptions: JwtAuthOptions = {
  issuer: ISSUER,
  audience: AUDIENCE,
  ttlMs: TTL_MS,
  clockToleranceMs: 5000,
  algorithms: ['EdDSA'],
  signingKey: { kid: 'ed-2026', alg: 'EdDSA', key: signing.privateKey },
  verificationKeys: [{ kid: 'ed-2026', alg: 'EdDSA', key: signing.publicKey }],
  clock,
};

@Controller('auth')
class AuthController {
  constructor(
    @Inject(AUTHENTICATION_SERVICE)
    private readonly auth: AuthenticationService,
  ) {}

  @Post('login')
  login(@Body() body: { username: string; password: string }) {
    return this.auth.loginWithPassword(body);
  }
}

@Controller()
class ThingsController {
  @Get('protected/things')
  @UseGuards(AuthenticationGuard)
  @RequirePermissions('things:read')
  things() {
    return { ok: true };
  }
}

@Module({
  imports: [
    FoundationCoreModule.withAuthentication({
      imports: [PortsModule, JwtAuthModule.register(jwtOptions)],
      ports: {
        identities: 'E2E_IDENTITIES',
        sessions: 'E2E_SESSIONS',
        tokens: JWT_AUTH_ISSUER,
        clock: 'E2E_CLOCK',
        password: 'E2E_PASSWORD',
      },
    }),
    FoundationCoreModule.withHttpSecurity({
      imports: [PortsModule, JwtAuthModule.register(jwtOptions)],
      ports: {
        tokens: JWT_AUTH_VERIFIER,
        sessions: 'E2E_SESSIONS',
        identities: 'E2E_IDENTITIES',
        clock: 'E2E_CLOCK',
      },
      operationTimeoutMs: 5000,
    }),
  ],
  controllers: [AuthController, ThingsController],
})
class AppModule {}

const b64 = (value: string) => Buffer.from(value).toString('base64url');

describe('JWT nativo com rotas protegidas (e2e)', () => {
  let app: INestApplication<App>;

  beforeAll(async () => {
    const moduleFixture = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    clock.current = START;
    clock.failing = false;
    sessions.clear();
  });

  const server = () => app.getHttpServer();
  const protectedGet = (token: string) =>
    request(server())
      .get('/protected/things')
      .set('Authorization', `Bearer ${token}`);

  async function login(): Promise<string> {
    const response = await request(server())
      .post('/auth/login')
      .send({ username: 'alice', password: 'correct-horse' });
    expect(response.status).toBe(201);
    return (response.body as { accessToken: string }).accessToken;
  }

  it('login emite JWT que abre a rota protegida com o ator atual', async () => {
    const token = await login();
    const response = await protectedGet(token);
    expect(response.status).toBe(200);
    expect(decodeJwt(token)).not.toHaveProperty('permissions');
  });

  it('rota protegida sem token responde 401', async () => {
    const response = await request(server()).get('/protected/things');
    expect(response.status).toBe(401);
  });

  it('token adulterado ou malformado responde 401', async () => {
    const token = await login();
    const [head = '', , sig = ''] = token.split('.');
    const forged = b64(JSON.stringify({ ...decodeJwt(token), sub: 'admin' }));
    expect((await protectedGet(`${head}.${forged}.${sig}`)).status).toBe(401);
    expect((await protectedGet('not-a-jwt')).status).toBe(401);
  });

  it('alg none responde 401', async () => {
    const claims = decodeJwt(await login());
    const none = `${b64(JSON.stringify({ alg: 'none', kid: 'ed-2026' }))}.${b64(JSON.stringify(claims))}.`;
    expect((await protectedGet(none)).status).toBe(401);
  });

  it('HS256 usando a chave pública como segredo responde 401', async () => {
    const claims = decodeJwt(await login());
    const hsToken = await new SignJWT({ ...claims })
      .setProtectedHeader({ alg: 'HS256', kid: 'ed-2026' })
      .sign(
        createSecretKey(
          Buffer.from(
            signing.publicKey.export({ type: 'spki', format: 'pem' }) as string,
          ),
        ),
      );
    expect((await protectedGet(hsToken)).status).toBe(401);
  });

  it('token assinado por emissor desconhecido responde 401', async () => {
    const forged = await new SignJWT({ sid: 'sess-1' })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'ed-2026' })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject('user-1')
      .setJti('forged')
      .setIssuedAt(Math.floor(START / 1000))
      .setNotBefore(Math.floor(START / 1000))
      .setExpirationTime(Math.floor(START / 1000) + 600)
      .sign(intruder.privateKey);
    expect((await protectedGet(forged)).status).toBe(401);
  });

  it('token expirado responde 401', async () => {
    const token = await login();
    clock.current += TTL_MS + 6000;
    expect((await protectedGet(token)).status).toBe(401);
  });

  it('sessão revogada invalida o token antes da expiração', async () => {
    const token = await login();
    const sid = (decodeJwt(token) as { sid: string }).sid;
    const row = sessions.get(sid);
    if (row) row.state = 'revoked';
    expect((await protectedGet(token)).status).toBe(401);
  });

  it('falha do verificador responde 503 sem vazar detalhe, nunca 200', async () => {
    const token = await login();
    clock.failing = true;
    const response = await protectedGet(token);
    expect(response.status).toBe(503);
    expect(JSON.stringify(response.body)).not.toMatch(/postgres|secret|clock/);
  });

  it('login emite token cuja expiração não passa da sessão', async () => {
    const response = await request(server())
      .post('/auth/login')
      .send({ username: 'alice', password: 'correct-horse' });
    const body = response.body as {
      accessToken: string;
      expiresAt: number;
      sessionId: string;
    };
    const row = sessions.get(body.sessionId);
    expect(body.expiresAt).toBeLessThanOrEqual(row?.expiresAt ?? 0);
    expect(body.expiresAt).toBe(START + TTL_MS);
  });
});

describe('composição sem verificador JWT (e2e)', () => {
  it('rota protegida sem registro de segurança não compila', async () => {
    @Controller()
    class OrphanController {
      @Get('orphan')
      @UseGuards(AuthenticationGuard)
      orphan() {
        return { ok: true };
      }
    }
    @Module({ controllers: [OrphanController] })
    class OrphanModule {}
    await expect(
      Test.createTestingModule({ imports: [OrphanModule] }).compile(),
    ).rejects.toThrow();
  });

  it('withHttpSecurity sem importar JwtAuthModule não compila', async () => {
    @Module({
      imports: [
        FoundationCoreModule.withHttpSecurity({
          imports: [PortsModule],
          ports: {
            tokens: JWT_AUTH_VERIFIER,
            sessions: 'E2E_SESSIONS',
            identities: 'E2E_IDENTITIES',
            clock: 'E2E_CLOCK',
          },
        }),
      ],
    })
    class MissingVerifierModule {}
    await expect(
      Test.createTestingModule({ imports: [MissingVerifierModule] }).compile(),
    ).rejects.toThrow();
  });
});
