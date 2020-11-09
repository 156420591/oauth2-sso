package io.lpgph.client;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebFluxSecurity
public class SecurityConfig {

  /**
   * 如果需要登录的 则在这里控制 登录页 该服务同时做为 <br>
   * 登录客户端服务<br>
   * 网关服务<br>
   * 资源服务<br>
   */
  @Bean
  SecurityWebFilterChain configure(ServerHttpSecurity http) {
    http.authorizeExchange(
            (exchanges) ->
                exchanges.pathMatchers("/login/**").permitAll().anyExchange().authenticated())
        .csrf()
        .disable()
        .oauth2Client(withDefaults());
    return http.build();
  }
}
