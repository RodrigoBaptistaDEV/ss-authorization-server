
# Authorization Server

Este projeto implementa um **Authorization Server (AS)** em **Spring Boot 3 + Spring Security + Spring Authorization Server**.  
Ele é responsável por autenticar **usuários administrativos** (com login local ou social via Google) e por emitir **tokens OAuth2/OpenID Connect** que podem ser consumidos por Resource Servers.

---

## 📐 Arquitetura

O projeto foi enxugado para atuar apenas como **Authorization Server**, separado de qualquer Resource Server.

### Principais pacotes

```

authorizationserver/
├─ client/        → CRUD de OAuth2 Clients (client\_id, client\_secret, scopes, redirect URIs)
├─ user/          → Autenticação de usuários administrativos
│   └─ loginsocial/ → Integração com login social (Google)
├─ security/      → Configuração de segurança (AS + login/admin)
├─ infra/         → Configuração de banco/datasource
└─ common/        → DTOs e exceptions genéricas

````

---

## 🔑 Fluxos de Autenticação

### 1. Autenticação de **clients**
- Um client (ex.: aplicação frontend) se registra no banco (`Client`, `ClientRepository`).
- O client usa `client_id` + `client_secret` (ou PKCE) para obter tokens.
- O Spring Authorization Server expõe endpoints padronizados:
  - `/.well-known/openid-configuration`
  - `/.well-known/jwks.json`
  - `/oauth2/token`
  - `/oauth2/authorize`

### 2. Autenticação de **usuários administrativos**
- Usuários humanos (`Usuario`) são armazenados no banco (`UsuarioRepository`).
- O login pode ser feito de duas formas:
  - **Local** → usando login/senha cadastrados.
  - **Social (Google)** → via `oauth2Login()` integrado ao Google.  
    O `LoginSocialSuccessHandler` cria/atualiza o `Usuario` localmente a partir do e-mail do Google.
- Cada `Usuario` recebe **roles** (ex.: `ROLE_GERENTE`), que habilitam ou não o acesso a endpoints administrativos.

### 3. Endpoints administrativos
- O `ClientController` expõe rotas para cadastrar/editar/remover clients.
- Protegido por `@PreAuthorize("hasRole('GERENTE')")`.
- Apenas usuários autenticados com `ROLE_GERENTE` podem gerenciar clients.

---

## ⚙️ Configurações de Segurança

O projeto possui **duas cadeias de filtros**:

1. **Authorization Server**  
   Definido em `AuthorizationServerConfiguration` com `@Order(1)`.  
   - Responsável por `/oauth2/**`, `/.well-known/**`, `/jwks`.  
   - Usa `OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)`.

2. **Login/Admin**  
   Definido em `SecurityConfiguration` com `@Order(2)`.  
   - Responsável por `/login`, `/logout`, `/admin/**`.  
   - Suporta `formLogin()` e `oauth2Login()` (Google).  
   - Aplica regras de role (`hasRole("GERENTE")`).

---

## 📦 Banco de Dados

- Tabelas principais:
  - `usuarios` → credenciais e perfil dos administradores.
  - `clients` → clients OAuth2 registrados.
- O segredo dos clients é armazenado de forma **hash** com `PasswordEncoder`.

---

## ▶️ Como rodar

1. Configure um banco (H2, Postgres, etc.) e ajuste em `application.yml`.
2. Configure o login social com Google (se desejado):

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope: openid, profile, email
        provider:
          google:
            issuer-uri: https://accounts.google.com
````

3. Suba o app:

```bash
./mvnw spring-boot:run
```

4. Endpoints disponíveis:

* `http://localhost:8080/oauth2/authorize`
* `http://localhost:8080/oauth2/token`
* `http://localhost:8080/.well-known/openid-configuration`
* `http://localhost:8080/admin/clients/**`

---

## 🔒 Resumo

* Este serviço atua exclusivamente como **Authorization Server**.
* **Clients** se autenticam via OAuth2 para obter tokens.
* **Usuários administrativos** se autenticam via **login local** ou **Google**, e só com `ROLE_GERENTE` podem gerenciar clients.
* Os **tokens JWT** emitidos podem ser validados por Resource Servers usando o `JWKS` publicado pelo AS.

---

## 📚 Referências

* [Spring Authorization Server](https://spring.io/projects/spring-authorization-server)
* [OAuth 2.1 RFC Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-01)
* [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)

```