/* eslint-disable @typescript-eslint/require-await -- dublês de porta assíncronos sem await */
/* eslint-disable @typescript-eslint/unbound-method -- Jest inspeciona métodos mock sem invocá-los. */
import { generateKeyPairSync } from 'node:crypto';
import { Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { decodeJwt } from 'jose';
import { AuthenticationService } from '@devtrack/foundation-api/contracts';
import { FoundationCoreModule } from '@devtrack/foundation-api/nest';
import { AUTHENTICATION_SERVICE } from '@devtrack/foundation-api/contracts';
import type {
  AuthenticationSessions,
  IdentityAccessResolver,
  PasswordCredentialsVerifier,
} from '@devtrack/foundation-api/contracts';
import type {
  AuthenticationMethod,
  Principal,
} from '@devtrack/foundation-api/contracts';
import type { SessionReference } from '@devtrack/foundation-api/contracts';
import { JwtAccessTokenAdapter } from './jwt-auth.adapter';
import {
  JWT_AUTH_ISSUER,
  JWT_AUTH_VERIFIER,
  JwtAuthModule,
} from './jwt-auth.module';
import { JwtAuthConfigError } from './jwt-auth.options';
import type { JwtAuthOptions } from './jwt-auth.options';

const NOW = 1_700_000_000_000;
const ed = generateKeyPairSync('ed25519');
const ed2 = generateKeyPairSync('ed25519');
const clock = { now: () => NOW };

function options(overrides: Partial<JwtAuthOptions> = {}): JwtAuthOptions {
  return {
    issuer: 'https://auth.foundation.test',
    audience: 'foundation-api',
    ttlMs: 15 * 60_000,
    clockToleranceMs: 5_000,
    algorithms: ['EdDSA'],
    signingKey: { kid: 'ed-2026', alg: 'EdDSA', key: ed.privateKey },
    verificationKeys: [{ kid: 'ed-2026', alg: 'EdDSA', key: ed.publicKey }],
    clock,
    ...overrides,
  };
}

describe('JwtAuthModule', () => {
  it('register expõe o mesmo adapter sob os dois tokens nomeados', async () => {
    @Module({ imports: [JwtAuthModule.register(options())] })
    class HostModule {}
    const app = await Test.createTestingModule({
      imports: [HostModule],
    }).compile();
    const issuer = app.get<JwtAccessTokenAdapter>(JWT_AUTH_ISSUER);
    const verifier = app.get<JwtAccessTokenAdapter>(JWT_AUTH_VERIFIER);
    expect(issuer).toBeInstanceOf(JwtAccessTokenAdapter);
    expect(issuer).toBe(verifier);
    expect(String(JWT_AUTH_ISSUER)).toBe(
      'Symbol(foundation.api.v1.native.jwt-auth.issuer)',
    );
    expect(String(JWT_AUTH_VERIFIER)).toBe(
      'Symbol(foundation.api.v1.native.jwt-auth.verifier)',
    );
    await app.close();
  });

  it('register com configuração inválida lança antes do boot', () => {
    expect(() =>
      JwtAuthModule.register(options({ clockToleranceMs: 61_000 })),
    ).toThrow(JwtAuthConfigError);
  });

  it('registerAsync com configuração inválida impede a inicialização', async () => {
    @Module({
      imports: [
        JwtAuthModule.registerAsync({
          useFactory: () =>
            options({
              algorithms: ['EdDSA'],
              signingKey: { kid: 'ed-2026', alg: 'EdDSA', key: ed2.privateKey },
            }),
        }),
      ],
    })
    class HostModule {}
    await expect(
      Test.createTestingModule({ imports: [HostModule] }).compile(),
    ).rejects.toThrow('Invalid JWT auth configuration');
  });

  it('registerAsync lê chaves e política de um provider interno', async () => {
    const CONFIG = Symbol('config');
    @Module({
      providers: [
        {
          provide: CONFIG,
          useValue: options({ issuer: 'https://from-config.test' }),
        },
      ],
      exports: [CONFIG],
    })
    class ConfigModule {}
    @Module({
      imports: [
        JwtAuthModule.registerAsync({
          imports: [ConfigModule],
          inject: [CONFIG],
          useFactory: (value: unknown) => value as JwtAuthOptions,
        }),
      ],
    })
    class HostModule {}
    const app = await Test.createTestingModule({
      imports: [HostModule],
    }).compile();
    const issuer = app.get<JwtAccessTokenAdapter>(JWT_AUTH_ISSUER);
    const issued = await issuer.issue({
      principal: { subjectId: 'user-1', permissions: [] },
      session: { id: 'sess-1', expiresAt: NOW + 60_000 },
      method: { kind: 'password' },
    });
    expect(decodeJwt(issued.value).iss).toBe('https://from-config.test');
    await app.close();
  });

  describe('integração com AuthenticationService', () => {
    function build() {
      const sessions = new Map<
        string,
        { subjectId: string; state: string; expiresAt: number }
      >();
      let counter = 0;
      const ports: {
        sessions: jest.Mocked<AuthenticationSessions>;
        identities: jest.Mocked<IdentityAccessResolver>;
        password: jest.Mocked<PasswordCredentialsVerifier>;
      } = {
        password: {
          verify: jest.fn().mockResolvedValue({ subjectId: 'user-1' }),
        },
        identities: {
          bySubject: jest.fn().mockResolvedValue({
            subjectId: 'user-1',
            permissions: ['things:read'],
            tenantId: 'tenant-a',
          }),
          byExternalIdentity: jest.fn().mockResolvedValue(null),
        },
        sessions: {
          createPending: jest.fn<
            Promise<SessionReference>,
            [Principal, AuthenticationMethod]
          >(async (principal) => {
            counter += 1;
            const id = `sess-${counter}`;
            const expiresAt = NOW + 45 * 60_000 + 1234;
            sessions.set(id, {
              subjectId: principal.subjectId,
              state: 'pending',
              expiresAt,
            });
            return { id, expiresAt };
          }),
          activate: jest.fn(async (id: string): Promise<void> => {
            const entry = sessions.get(id);
            if (entry) entry.state = 'active';
          }),
          revoke: jest.fn<Promise<void>, [string]>(() => Promise.resolve()),
        },
      };
      return { ports, sessions };
    }

    it('login devolve token JWT cujo verify bate com sessão e subject', async () => {
      const { ports } = build();
      const adapter = new JwtAccessTokenAdapter(options());
      const service = new AuthenticationService({
        password: ports.password,
        identities: ports.identities,
        sessions: ports.sessions,
        tokens: adapter,
        clock,
      });

      const result = await service.loginWithPassword({
        username: 'alice',
        password: 'x',
      });
      expect(result.tokenType).toBe('Bearer');
      expect(result.expiresAt % 1000).toBe(0);
      expect(result.expiresAt).toBeLessThanOrEqual(NOW + 45 * 60_000 + 1234);

      await expect(adapter.verify(result.accessToken)).resolves.toEqual({
        subjectId: 'user-1',
        sessionId: result.sessionId,
        expiresAt: result.expiresAt,
      });
      expect(decodeJwt(result.accessToken)).not.toHaveProperty('permissions');
      expect(decodeJwt(result.accessToken)).not.toHaveProperty('tenantId');
    });

    it('falha ao ativar a sessão não entrega token e revoga a pendente', async () => {
      const { ports } = build();
      ports.sessions.activate.mockRejectedValueOnce(new Error('db down'));
      const adapter = new JwtAccessTokenAdapter(options());
      const service = new AuthenticationService({
        password: ports.password,
        identities: ports.identities,
        sessions: ports.sessions,
        tokens: adapter,
        clock,
      });
      await expect(
        service.loginWithPassword({ username: 'alice', password: 'x' }),
      ).rejects.toThrow('authentication_unavailable');
      expect(ports.sessions.revoke).toHaveBeenCalledWith('sess-1');
    });

    it('registro Nest do adapter é aceito pelo AUTHENTICATION_SERVICE', async () => {
      const { ports } = build();
      @Module({
        providers: [
          { provide: 'IDENTITIES', useValue: ports.identities },
          { provide: 'SESSIONS', useValue: ports.sessions },
          { provide: 'CLOCK', useValue: clock },
          { provide: 'PASSWORD', useValue: ports.password },
        ],
        exports: ['IDENTITIES', 'SESSIONS', 'CLOCK', 'PASSWORD'],
      })
      class PortsModule {}
      @Module({
        imports: [
          FoundationCoreModule.withAuthentication({
            imports: [JwtAuthModule.register(options()), PortsModule],
            ports: {
              identities: 'IDENTITIES',
              sessions: 'SESSIONS',
              tokens: JWT_AUTH_ISSUER,
              clock: 'CLOCK',
              password: 'PASSWORD',
            },
          }),
        ],
      })
      class RootModule {}
      const app = await Test.createTestingModule({
        imports: [RootModule],
      }).compile();
      const service = app.get<AuthenticationService>(AUTHENTICATION_SERVICE);
      const result = await service.loginWithPassword({
        username: 'alice',
        password: 'x',
      });
      expect(result.accessToken.split('.')).toHaveLength(3);
      await app.close();
    });
  });
});
