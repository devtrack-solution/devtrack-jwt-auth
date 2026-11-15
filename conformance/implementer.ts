// Fixture de implementador (kit de conformidade, D8): o adapter publicado satisfaz as portas
// da Foundation que o módulo declara fornecer (access-token: emissor e verificador).
import type {
  AccessTokenIssuer,
  AccessTokenVerifier,
} from '@devtrack-solution/foundation-api/contracts';
import { JwtAccessTokenAdapter, type JwtAuthOptions } from '@devtrack-solution/jwt-auth';

declare const options: JwtAuthOptions;

const adapter = new JwtAccessTokenAdapter(options);
export const issuer: AccessTokenIssuer = adapter;
export const verifier: AccessTokenVerifier = adapter;
