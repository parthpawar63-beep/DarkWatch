package com.parth.darkwebmonitor.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http) throws Exception {

        http
            .authorizeHttpRequests(auth -> auth

                .requestMatchers(
                        "/css/**"
                ).permitAll()

                .requestMatchers(
                        "/",
                        "/history",
                        "/alerts",
                        "/monitoring",
                        "/monitoring/check/**",
                        "/monitoring/delete/**",
                        "/tor-status",
                        "/intelligence",
                        "/reports",
                        "/reports/pdf",
                        "/scan",
                        "/monitoring/add"
                ).authenticated()

                .anyRequest().authenticated()
            )

            .formLogin(form -> form
                    .defaultSuccessUrl("/", true)
                    .permitAll()
            )

            .csrf(csrf -> csrf
                    .ignoringRequestMatchers(
                            "/scan",
                            "/monitoring/add"
                    )
            );

        return http.build();
    }
}
