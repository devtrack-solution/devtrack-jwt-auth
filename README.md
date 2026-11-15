# @devtrack-solution/jwt-auth

Módulo oficial JWT Auth da DevTrack Foundation. Implementa as portas `AccessTokenIssuer` e `AccessTokenVerifier` da Foundation sobre `jose@5.10.0` (versão exata; a 6 é ESM-only):

- política de algoritmos fechada: EdDSA e ES256;
- chaves por `kid` com rotação;
- claims mínimas: `iss`, `aud`, `exp`, `nbf`, sem permissões no token;
- tolerância de relógio de no máximo 60 s e vida útil máxima validada;
- configuração verificada no boot.

Fornece a capacidade `access-token` major 1. É uma extensão npm: entra na API pelo `api-cli`, nunca por cópia de arquivos.

## Instalação

Pré-requisito: um host com `@devtrack-solution/foundation-api` `^0.1.0` e `@nestjs/common` `^11`. Com o registry configurado no `.npmrc` (`@devtrack-solution:registry=…`, ver `foundation-api/docs/publishing.md`):

```bash
# api-cli do workspace (bin `api-cli` de ../api-cli); --foundation aponta para o host
api-cli --foundation ./foundation-api install @devtrack-solution/jwt-auth@0.1.0 --registry "$DEVTRACK_REGISTRY"
api-cli --foundation ./foundation-api setting enable-native native/http-security
```

Os dois comandos regeneram a composição (`npm run compose`) ao final.

O `api-cli` valida integridade (sha512 do registry contra o tarball), versão exata, peers contra o host e o descriptor. Depois registra `ext/jwt-auth` no perfil e em `src/composition/extension-sources.ts`. Para proteger rotas, `native/http-security` precisa estar selecionado: `access-token` sozinho não protege nada.

## Configuração

A configuração nunca vai no perfil. O host fornece as opções pelo token de host `jwt-auth.options`, declarado no bloco `composition` do descriptor. O módulo gerado expõe esse token como `COMPOSITION_HOST_TOKENS.jwtAuthOptions`, com valor `Symbol.for('foundation.api.v1.host.jwt-auth.options')`:

```ts
import { generateKeyPairSync } from 'node:crypto';
import type { JwtAuthOptions } from '@devtrack-solution/jwt-auth';
import { COMPOSITION_HOST_TOKENS } from './composition/composition.generated';

const { privateKey, publicKey } = generateKeyPairSync('ed25519'); // em produção, do cofre
const jwtOptions: JwtAuthOptions = {
  issuer: 'https://auth.example.com',
  audience: 'my-api',
  ttlMs: 15 * 60_000,
  clockToleranceMs: 1_000,
  algorithms: ['EdDSA'],
  signingKey: { kid: 'k1', alg: 'EdDSA', key: privateKey },
  verificationKeys: [{ kid: 'k1', alg: 'EdDSA', key: publicKey }],
  clock: { now: () => Date.now() },
};

// num módulo @Global() do host:
// { provide: COMPOSITION_HOST_TOKENS.jwtAuthOptions, useValue: jwtOptions }
```

Sem o token, o boot falha com a descrição `foundation.api.v1.host.jwt-auth.options`, e a rota nunca abre.

Uso direto, sem o gerador de composição: `JwtAuthModule.register(options)` ou `registerAsync({ inject, useFactory })`, com `JWT_AUTH_ISSUER` em `withAuthentication({ ports: { tokens } })` e `JWT_AUTH_VERIFIER` em `withHttpSecurity({ ports: { tokens } })`.

## Descriptor

`@devtrack-solution/jwt-auth/descriptor` (`dist/jwt-auth.descriptor.json`) contém só metadata:

```json
{
  "id": "ext/jwt-auth",
  "provides": [{ "id": "access-token", "major": 1 }],
  "composition": {
    "hostOptions": { "token": "jwt-auth.options", "type": "JwtAuthOptions" },
    "capabilityTokens": { "access-token": "JWT_AUTH_VERIFIER" }
  }
}
```

## Desenvolvimento

- No workspace, `scripts/link-foundation.mjs` (rodado antes de build, typecheck e testes) liga `node_modules/@devtrack-solution/foundation-api` à pasta irmã `../foundation-api`. Fora do workspace, não faz nada, e a Foundation vem do registry. O lockfile não grava URL de registry (`.npmrc` com `omit-lockfile-registry-resolved=true`); em qualquer ambiente, `npm ci` precisa de `@devtrack-solution:registry` configurado no `.npmrc` do usuário ou do pipeline (ver `docs/publishing.md` da Foundation).
- `npm run typecheck`, `npm run lint:check`, `npm test` (unitários e e2e), `npm run test:boundaries`.
- Fronteira: o código só importa `@devtrack-solution/foundation-api/contracts` e `/nest`. O `prepack` roda a verificação de publicação e a de fronteira.
- CI: `.github/workflows/ci.yml` (GitHub Actions) roda a qualidade do pacote e a conformidade contra a Foundation publicada (checkout do `devtrack-foundation-core` na tag do peer e `npm run conformance:published`). Conformidade `failed` ou `incomplete` bloqueia a publicação, que só acontece em tag `v<versão>`. Variáveis e detalhes: `docs/publishing.md` da Foundation, seção "CI".

## Limites

- Sem RS256 e sem gestão operacional de chaves (rotação, cofre e JWKS publicado ficam com o host).
- Licença MIT (arquivo `LICENSE`).
