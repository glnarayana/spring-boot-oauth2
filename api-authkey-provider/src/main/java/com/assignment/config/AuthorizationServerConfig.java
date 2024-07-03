package com.assignment.config;

import com.assignment.utils.JwtUtils;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @author Lakshminarayana Golla
 * Created on 01-07-2024
 **/
@Configuration
public class AuthorizationServerConfig {

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        // Configure OAuth2 Login
//        http
//                .oauth2Login(OAuth2LoginConfigurer::disable)
//                .oauth2ResourceServer(c -> c.jwt(Customizer. withDefaults()));
//
//        return http.build();
//    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());
        return http.formLogin(withDefaults()).build();
    }

//    @Bean
//    public OAuth2TokenGenerator<OAuth2Token> tokenGenerator() {
//        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource());
//        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
//        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
//        accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer());
//        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
//        return new DelegatingOAuth2TokenGenerator(
//                jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
//    }
//@Bean
//OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
//    JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
//    jwtGenerator.setJwtCustomizer(tokenCustomizer());
//    OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
//    OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
//    return new DelegatingOAuth2TokenGenerator(
//            jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
//}
//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
//        return (context) -> {
//            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
//                OAuth2ClientAuthenticationToken authentication = context.getPrincipal();
////                User user = (User) authentication.getPrincipal();
//
//                context.getClaims().claim("userId", "test");
//            }
//        };
//    }

    @Bean
    public JdbcRegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        RegisteredClient testClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("test-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .redirectUri("http://127.0.0.1:8080/redirect/")

                .scope("read-access")
                .build();
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//                .build();

        // Save registered client's in db as if in-memory
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        registeredClientRepository.save(testClient);

        return registeredClientRepository;
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = JwtUtils.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public EmbeddedDatabase embeddedDatabase() {
        return new EmbeddedDatabaseBuilder()
                .generateUniqueName(true)
                .setType(EmbeddedDatabaseType.H2)
                .setScriptEncoding(StandardCharsets.UTF_8.displayName())
                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
                .addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
                .build();
    }

}
