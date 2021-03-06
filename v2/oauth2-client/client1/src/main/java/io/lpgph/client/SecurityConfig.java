package io.lpgph.client;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

  @Bean
  SecurityWebFilterChain configure(ServerHttpSecurity http) {
    return http.authorizeExchange((exchanges) -> exchanges.anyExchange().authenticated())
        .csrf()
        .disable()
        .logout()
        .disable()
        .cors(spec -> spec.configurationSource(corsConfigurationSource()))
        .oauth2Login(withDefaults()) // 启用SSO支持 相当于@EnableOAuth2Sso
        //            .oauth2Client(client->client.authenticationManager( ));
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
    UrlBasedCorsConfigurationSource configurationSource = new UrlBasedCorsConfigurationSource();
    configurationSource.registerCorsConfiguration("/**", corsConfiguration);
    return configurationSource;
  }
}
