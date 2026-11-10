import { Module } from '@nestjs/common';
import type {
  DynamicModule,
  InjectionToken,
  ModuleMetadata,
  Provider,
} from '@nestjs/common';
import { JwtAccessTokenAdapter } from './jwt-auth.adapter';
import type { JwtAuthOptions } from './jwt-auth.options';

/**
 * Token do AccessTokenIssuer nativo. Passe em
 * FoundationCoreModule.withAuthentication({ ports: { tokens: JWT_AUTH_ISSUER } }).
 */
export const JWT_AUTH_ISSUER: InjectionToken = Symbol.for(
  'foundation.api.v1.native.jwt-auth.issuer',
);
/**
 * Token do AccessTokenVerifier nativo. Passe em
 * FoundationCoreModule.withHttpSecurity({ ports: { tokens: JWT_AUTH_VERIFIER } }).
 */
export const JWT_AUTH_VERIFIER: InjectionToken = Symbol.for(
  'foundation.api.v1.native.jwt-auth.verifier',
);

/** Interno: instância única do adapter, compartilhada pelos dois tokens. */
const JWT_AUTH_ADAPTER: InjectionToken = Symbol.for(
  'foundation.api.v1.native.jwt-auth.adapter',
);

export interface JwtAuthAsyncOptions {
  readonly imports?: ModuleMetadata['imports'];
  readonly inject?: readonly InjectionToken[];
  /** Devolve a configuração (ex.: lida de um cofre). Falha de validação impede o boot. */
  readonly useFactory: (
    ...args: unknown[]
  ) => JwtAuthOptions | Promise<JwtAuthOptions>;
}

function adapterProviders(): Provider[] {
  return [
    { provide: JWT_AUTH_ISSUER, useExisting: JWT_AUTH_ADAPTER },
    { provide: JWT_AUTH_VERIFIER, useExisting: JWT_AUTH_ADAPTER },
  ];
}

/**
 * Módulo nativo de JWT. Não é habilitado implicitamente: só entra no grafo se o
 * host importá-lo. A configuração inválida lança já em register/registerAsync.
 */
@Module({})
export class JwtAuthModule {
  static register(options: JwtAuthOptions): DynamicModule {
    // Construção eager: valida a política e lança antes de o Nest iniciar.
    const adapter = new JwtAccessTokenAdapter(options);
    return {
      module: JwtAuthModule,
      providers: [
        { provide: JWT_AUTH_ADAPTER, useValue: adapter },
        ...adapterProviders(),
      ],
      exports: [JWT_AUTH_ISSUER, JWT_AUTH_VERIFIER],
    };
  }

  static registerAsync(options: JwtAuthAsyncOptions): DynamicModule {
    if (typeof options?.useFactory !== 'function')
      throw new Error('Invalid JWT auth registration: useFactory');
    return {
      module: JwtAuthModule,
      imports: options.imports,
      providers: [
        {
          provide: JWT_AUTH_ADAPTER,
          inject: [...(options.inject ?? [])],
          useFactory: async (...args: unknown[]) =>
            new JwtAccessTokenAdapter(await options.useFactory(...args)),
        },
        ...adapterProviders(),
      ],
      exports: [JWT_AUTH_ISSUER, JWT_AUTH_VERIFIER],
    };
  }
}
