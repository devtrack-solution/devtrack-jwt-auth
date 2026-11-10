export {
  JWT_AUTH_ISSUER,
  JWT_AUTH_VERIFIER,
  JwtAuthModule,
} from './jwt-auth.module';
export type { JwtAuthAsyncOptions } from './jwt-auth.module';
export { JwtAccessTokenAdapter } from './jwt-auth.adapter';
export {
  JWT_AUTH_ALGORITHMS,
  JwtAuthConfigError,
  JWT_AUTH_MAX_CLOCK_TOLERANCE_MS,
  JWT_AUTH_MAX_TTL_MS,
} from './jwt-auth.options';
export type {
  JwtAuthAlgorithm,
  JwtAuthKeyMaterial,
  JwtAuthOptions,
  JwtAuthSigningKey,
  JwtAuthVerificationKey,
} from './jwt-auth.options';
export {
  JWT_AUTH_MODULE_ID,
  jwtAuthComposition,
  jwtAuthModuleDescriptor,
} from './descriptor';
