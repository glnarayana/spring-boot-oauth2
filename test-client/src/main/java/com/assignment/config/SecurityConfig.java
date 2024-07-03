package com.assignment.config;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Lakshminarayana Golla
 * Created on 03-07-2024
 **/
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, OAuth2ResourceServerProperties properties) throws Exception {
        http.authorizeHttpRequests(authorize ->
                        authorize
                                .requestMatchers("/**/public/**").permitAll()
                                .requestMatchers("/**/actuator/**").permitAll()
                                .anyRequest().authenticated())
                .csrf(AbstractHttpConfigurer::disable);
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder(properties))));
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder(OAuth2ResourceServerProperties properties) {
        return NimbusJwtDecoder
                .withJwkSetUri(properties.getJwt().getJwkSetUri())
                .jwsAlgorithm(SignatureAlgorithm.RS256).build();
    }

}
