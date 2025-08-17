package io.github.cursodsousa.libraryapi.authorizationServer.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.github.cursodsousa.libraryapi.authorizationServer.user.loginsocial.CustomAuthentication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/*
========================================================================================================================
GUIA COMPLETO (EM COMENTÁRIOS) — AUTHORIZATION SERVER COM JWT (Spring Authorization Server + Nimbus JOSE/JWT)
========================================================================================================================

⚡ Visão geral rápida
- Authorization Server (AS): componente que autentica usuários/clients e emite tokens OAuth2/OIDC.
- Resource Server (RS): API(s) que recebem o token no Authorization header (Bearer ...) e validam/extraem claims.
- JWT (JSON Web Token): token auto-contido (SELF_CONTAINED), assinado (JWS). O AS publica a chave pública via JWKS.
- JWKS (JWK Set): endpoint com as chaves públicas do AS para verificação de assinatura pelos RS/clients.
- OIDC (OpenID Connect): camada de identidade sobre OAuth2 (id_token, userinfo, logout etc.).

🧩 Papéis e fluxos
- Resource Owner: o usuário.
- Client: App front/back que pede autorização e troca por token (ex.: SPA, mobile, backend).
- Authorization Server: valida credenciais, executa consentimento e emite tokens.
- Resource Server: protege endpoints e valida tokens.

Fluxos comuns:
1) Authorization Code + PKCE (usuário final): Navegador → /oauth2/authorize → redireciona → /oauth2/token.
2) Client Credentials (serviço-para-serviço): POST direto no /oauth2/token com grant_type=client_credentials.
3) Refresh Token: troca refresh_token por novo access_token.
4) (Opcional) Introspection: para “reference tokens” (aqui usaremos SELF_CONTAINED/JWT; introspecção fica menos usada).

🔐 Tokens e formatos
- Access Token: curto prazo (ex.: 60 minutos). Deve conter claims úteis (sub, scope, authorities, etc).
- Refresh Token: vida mais longa (não mostrado nesta classe, mas suportado pelo Spring Authorization Server).
- SELF_CONTAINED: o access token é um JWT assinado; RS valida localmente usando a JWKS do AS.
- REFERENCE: token opaco (id) que exige introspection no AS para validar.

🛠️ Chaves criptográficas (JWK/JWKS)
- Este exemplo gera um par RSA 2048 em memória a cada startup (bom p/ estudo, ruim em produção).
- Em produção: persistir/gerenciar chaves de forma segura (keystore, HSM/KMS), rotacionar e publicar no JWKS.
- Algoritmo: RSA (padrão), mas EC (P-256, P-384) também é comum e mais leve.

🧱 Organização desta classe
- SecurityFilterChain (AS + OIDC + resource server no mesmo app).
- PasswordEncoder (BCrypt).
- TokenSettings/ClientSettings (parâmetros de emissão de token e consentimento).
- JWKSource + geração RSA (publicação no JWKS).
- JwtDecoder (baseado no JWKSource).
- AuthorizationServerSettings (caminhos dos endpoints do AS).
- OAuth2TokenCustomizer (enriquece JWT com claims customizadas).

✅ O que não está aqui (mas você precisará no projeto real)
- RegisteredClientRepository: cadastro dos clients (client_id/secret, scopes, redirect_uris, grant_types, etc.).
  → Exemplo de snippet comentado mais abaixo.
- UserDetailsService / AuthenticationProvider: como os usuários/credenciais são validados.
- Páginas de login (/login) e consentimento (se habilitado).
- HTTPS/TLS, CORS, CSRF apropriados, logs, observabilidade, testes com Testcontainers, etc.

📎 Dicas práticas
- Em APIs internas/microserviços, considere Client Credentials.
- Em apps SPA/mobile, use Authorization Code + PKCE (sempre!).
- Defina “aud” e “scope” com cuidado; só entregue o mínimo necessário.
- Evite colocar dados sensíveis no JWT (qualquer RS verá as claims—apesar de assinadas, não são criptografadas por padrão).
- Em produção, configure key rotation e mantenha pelo menos 2 chaves ativas (kid diferentes) no JWKS.

🧪 Teste rápido via curl (Client Credentials)
- Pré-condição: ter um RegisteredClient com grant_type=client_credentials e scope=read (por exemplo).
- Exemplo:
  curl -u client-id:client-secret \
    -d "grant_type=client_credentials&scope=read" \
    http://localhost:8080/oauth2/token
- Resposta: JSON com access_token (JWT). Valide header/payload em jwt.io ou via Nimbus.

🧪 Teste rápido via navegador (Authorization Code + PKCE)
1) Redirecione usuário p/ /oauth2/authorize?response_type=code&client_id=...&redirect_uri=...&scope=openid%20profile&code_challenge=...&code_challenge_method=S256
2) Após login/consentimento, troque code por token em /oauth2/token com code_verifier.

🚨 Observações importantes deste arquivo
- Este AS também habilita o Resource Server na mesma aplicação (jwt()). Em produção, é comum separar serviços.
- As claims extras (“authorities”, “email”) são adicionadas somente no ACCESS_TOKEN e quando o principal é CustomAuthentication.
  Garanta que “CustomAuthentication” preencha getAuthorities() e getUsuario().getEmail() corretamente.

*/

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfiguration {

    /**
     * Define a corrente de filtros (FilterChain) do Authorization Server.
     *
     * Conceito:
     * - Aplica a configuração padrão do Spring Authorization Server (endpoints OAuth2/OIDC).
     * - Habilita OIDC (id_token, discovery, userinfo, logout).
     * - Também habilita este MESMO app como Resource Server (validação de JWT em endpoints que você proteger).
     * - Usa formulário de login padrão do Spring Security em /login (para fluxos Authorization Code).
     */
    @Bean
    @Order(1) // garante que esta chain tenha prioridade quando houver mais chains
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {

        // Registra toda a infra básica do Authorization Server:
        // endpoints como /oauth2/authorize, /oauth2/token, /.well-known/openid-configuration etc.
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http); // <<< configura endpoints e filtros do AS

        // Habilita o suporte OpenID Connect por cima do OAuth2 (id_token, userinfo, logout, discovery).
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults()); // <<< ativa OIDC com as convenções/URLs padrão

        // Define que o login (para usuários finais em fluxos Authorization Code) usará a página /login.
        // Se você tiver uma página customizada, mapeie aqui.
        http.formLogin(configurer -> configurer.loginPage("/login")); // <<< fluxo de autenticação interativo

        return http.build();
    }

    /**
     * PasswordEncoder para senhas de usuários e/ou clients confidenciais.
     * Conceito: BCrypt com força 10 (equilíbrio entre segurança e performance).
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(10); // <<< ajuste a “strength” conforme a performance do seu ambiente
    }

    /**
     * Configurações de token (lado do emissor/AS).
     * - SELF_CONTAINED: access_token será um JWT assinado (verificável offline via JWKS).
     * - TTL do access token: 60 minutos.
     */
    @Bean
    public TokenSettings tokenSettings(){
        return TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED) // <<< emite JWT (não token opaco)
                .accessTokenTimeToLive(Duration.ofMinutes(60))        // <<< tempo de vida do access_token
                .build();
    }

    /**
     * Configurações padrão aplicáveis aos clientes (complementa o RegisteredClient).
     * - requireAuthorizationConsent(false): sem tela de consentimento (útil em ambientes controlados).
     */
    @Bean
    public ClientSettings clientSettings(){
        return ClientSettings.builder()
                .requireAuthorizationConsent(false) // <<< para apps internos; em públicos, prefira true
                .build();
    }

    // JWK - JSON Web Key
    /**
     * Fonte de chaves (JWKSource) usada para assinar os JWTs e publicar o JWKS.
     * Conceito:
     * - Aqui geramos uma chave RSA em memória (bom para estudo; em produção, persista/rotacione com KMS/keystore).
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {
        RSAKey rsaKey = gerarChaveRSA(); // <<< chave RSA (contém pública e privada)
        JWKSet jwkSet = new JWKSet(rsaKey); // <<< conjunto de chaves que será exposto no endpoint JWKS
        return new ImmutableJWKSet<>(jwkSet); // <<< implementação imutável para o Spring usar
    }

    // Gerar par de chaves RSA
    /**
     * Gera um par de chaves RSA 2048 e encapsula em um RSAKey (Nimbus) com um 'kid' aleatório.
     * Observação:
     * - Em produção, NÃO gere a cada startup; armazene com segurança e faça rotação planejada.
     */
    private RSAKey gerarChaveRSA() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA"); // <<< algoritmo RSA
        keyPairGenerator.initialize(2048);                                       // <<< tamanho da chave
        KeyPair keyPair = keyPairGenerator.generateKeyPair();                    // <<< gera o par

        RSAPublicKey chavePublica = (RSAPublicKey) keyPair.getPublic();  // <<< parte pública (vai no JWKS)
        RSAPrivateKey chavePrivada = (RSAPrivateKey) keyPair.getPrivate(); // <<< parte privada (assina tokens)

        return new RSAKey
                .Builder(chavePublica)                 // <<< inicia com a pública
                .privateKey(chavePrivada)              // <<< associa a privada (para assinatura)
                .keyID(UUID.randomUUID().toString())   // <<< define um 'kid' (usado no header do JWT)
                .build();
    }

    /**
     * Decoder de JWT para o Resource Server (neste app).
     * Conceito:
     * - Usa o JWKSource acima para verificar assinaturas dos tokens recebidos.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource){
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource); // <<< cria um JwtDecoder baseado no JWK
    }

    /**
     * Settings do Authorization Server (URLs dos endpoints).
     * Observações:
     * - 'oidcUserInfoEndpoint' abaixo está como "/oauth2/iserinfo" (provável typo). O padrão OIDC é "/userinfo".
     *   Se quiser o padrão, remova essa customização ou altere para o path correto.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings(){
        return AuthorizationServerSettings.builder()
                .tokenEndpoint("/oauth2/token")            // <<< troca code/credenciais por tokens
                .tokenIntrospectionEndpoint("/oauth2/introspect") // <<< usado p/ referência/opaque tokens (menos comum com JWT)
                .tokenRevocationEndpoint("/oauth2/revoke") // <<< revogação (refresh/access conforme suporte)
                .authorizationEndpoint("/oauth2/authorize")// <<< início do fluxo Authorization Code
                .oidcUserInfoEndpoint("/oauth2/iserinfo")  // <<< CUIDADO: se quiser o padrão OIDC, use "/userinfo"
                .jwkSetEndpoint("/oauth2/jwks")            // <<< JWKS: RS e clientes obtêm a(s) chave(s) pública(s)
                .oidcLogoutEndpoint("/oauth2/logout")      // <<< RP-Initiated Logout (requer configuração OIDC)
                .build();
    }

    /**
     * Customizador de tokens JWT no momento da emissão.
     * Conceito:
     * - Só adiciona claims extras quando o token sendo emitido é o ACCESS_TOKEN.
     * - Só executa se a Authentication for do tipo CustomAuthentication (seu tipo custom).
     * - Adiciona:
     *   - "authorities": roles/perfis do usuário (útil para autorização no Resource Server).
     *   - "email": e-mail do usuário autenticado.
     * Boas práticas:
     * - Evite colocar dados sensíveis no JWT; ele é legível por quem possuir o token.
     * - Padronize os nomes das claims (ex.: "roles" vs "authorities").
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(){
        return context -> {
            var principal = context.getPrincipal(); // <<< Authentication do usuário/cliente no momento da emissão

            if(principal instanceof CustomAuthentication authentication){ // <<< só customiza se for seu tipo custom
                OAuth2TokenType tipoToken = context.getTokenType();       // <<< qual token está sendo gerado? access? id?

                if(OAuth2TokenType.ACCESS_TOKEN.equals(tipoToken)){       // <<< adiciona claims apenas no access_token
                    Collection<GrantedAuthority> authorities = authentication.getAuthorities(); // <<< authorities do principal
                    List<String> authoritiesList =
                            authorities.stream().map(GrantedAuthority::getAuthority).toList(); // <<< ["ROLE_ADMIN", "SCOPE_read", ...]

                    // As claims são adicionadas no payload do JWT.
                    context
                            .getClaims()
                            .claim("authorities", authoritiesList)                     // <<< roles/scopes úteis para autorização no RS
                            .claim("email", authentication.getUsuario().getEmail());   // <<< info de identidade conveniente
                }
            }

        };
    }
}