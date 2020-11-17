package io.lpgph.gateway;

import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebFluxSecurity
public class SecurityConfig {

  @Order(Ordered.HIGHEST_PRECEDENCE)
  @Bean
  SecurityWebFilterChain apiHttpSecurity(ServerHttpSecurity http) {
    return http.securityMatcher(new PathPatternParserServerWebExchangeMatcher("/api/**"))
        .authorizeExchange((exchanges) -> exchanges.anyExchange().permitAll())
        .csrf()
        .disable()
        .build();
  }

  @Bean
  SecurityWebFilterChain httpSecurity(ServerHttpSecurity http) {
    return http.authorizeExchange(
            (exchanges) ->
                exchanges
                    .pathMatchers("/login/**", "/login**")
                    .permitAll()
                    .anyExchange()
                    .authenticated())
        .csrf()
        .disable()
        .cors(spec -> spec.configurationSource(corsConfigurationSource()))
        .oauth2Login(withDefaults())
        .build();
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration corsConfiguration = new CorsConfiguration();
    corsConfiguration.addAllowedOrigin("*");
    corsConfiguration.addAllowedHeader("*");
    corsConfiguration.addAllowedMethod("*");
    corsConfiguration.setAllowCredentials(true);
    corsConfiguration.setMaxAge(3600L);
    corsConfiguration.addExposedHeader("access-control-allow-methods");
    corsConfiguration.addExposedHeader("access-control-allow-headers");
    corsConfiguration.addExposedHeader("access-control-allow-origin");
    corsConfiguration.addExposedHeader("access-control-max-age");
    corsConfiguration.addExposedHeader("X-Frame-Options");
    corsConfiguration.addExposedHeader("Authorization");
    UrlBasedCorsConfigurationSource configurationSource = new UrlBasedCorsConfigurationSource();
    configurationSource.registerCorsConfiguration("/**", corsConfiguration);
    return configurationSource;
  }
}
