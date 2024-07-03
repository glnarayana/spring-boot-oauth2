package com.assignment.config;

/**
 * @author Lakshminarayana Golla
 * Created on 01-07-2024
 **/
//@Configuration
public class SecurityConfig {

    private static final String LOGIN_URL = "/login";

//    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
//    String issuerUri;

//    @Bean
//    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(authorize ->
//                        authorize
//                                .requestMatchers("/oauth2/**").permitAll()
//                                .requestMatchers("/public/**").permitAll()
//                                .requestMatchers("/actuator/**").permitAll()
//                                .anyRequest().authenticated()
//                ).csrf(AbstractHttpConfigurer::disable)
//                .formLogin(formLogin -> formLogin.loginPage(LOGIN_URL));
////        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(JwtDecoders.fromIssuerLocation(issuerUri))));
//
//
//        return http.build();
//    }

}
