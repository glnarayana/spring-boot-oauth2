package com.assignment.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @author Lakshminarayana Golla
 * Created on 01-07-2024
 **/
@EnableWebSecurity
public class SecurityConfig {

    private static final String LOGIN_URL = "/login";

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(authorize ->
//                        authorize
//                                .requestMatchers("/public/**").permitAll()
////                                .requestMatchers("/issuer/**").permitAll()
//                                .anyRequest().authenticated()
//                );
////                .formLogin(formLogin -> formLogin.loginPage(LOGIN_URL));
////                .oauth2Login(oauth2Login ->
////                        oauth2Login.loginPage(LOGIN_URL)
////                                .successHandler(authenticationSuccessHandler())
////                );
//
//        return http.build();
        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest()
                        .authenticated())
                .formLogin(withDefaults());
        return http.build();
    }

//    private AuthenticationSuccessHandler authenticationSuccessHandler() {
//        return new FederatedIdentityAuthenticationSuccessHandler();
//    }

    // @formatter:off
    @Bean
    public UserDetailsService users() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user1")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
    // @formatter:on

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

}
