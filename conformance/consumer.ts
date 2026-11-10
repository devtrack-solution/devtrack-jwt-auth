// Fixture de consumidor (kit de conformidade, D8): uso da API pública pelo nome do pacote.
import type { DynamicModule } from '@nestjs/common';
import {
  JWT_AUTH_ISSUER,
  JWT_AUTH_VERIFIER,
  JwtAuthModule,
  jwtAuthModuleDescriptor,
  type JwtAuthOptions,
} from '@devtrack/jwt-auth';

declare const options: JwtAuthOptions;

export const registration: DynamicModule = JwtAuthModule.register(options);
export const asyncRegistration: DynamicModule = JwtAuthModule.registerAsync({
  inject: [],
  useFactory: () => options,
});
export const tokens = [JWT_AUTH_ISSUER, JWT_AUTH_VERIFIER] as const;
export const provides: string = jwtAuthModuleDescriptor.provides[0].id;
