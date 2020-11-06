package io.lpgph.client;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebFluxSecurity
public class SecurityConfig {
    @Bean
    SecurityWebFilterChain configure(ServerHttpSecurity http) {
        http
                .authorizeExchange((exchanges) ->
                                exchanges
//                                .pathMatchers("/login/**").permitAll()
                                        .anyExchange().authenticated()
                )
                .csrf().disable()
                .oauth2Login(withDefaults());
        return http.build();
    }


}
