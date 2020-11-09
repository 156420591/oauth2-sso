package io.lpgph.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Slf4j
@AllArgsConstructor
@RestController
public class LoginController {

  private final ReactiveClientRegistrationRepository reactiveClientRegistrationRepository;

  private final WebClient webClient;

  private final ObjectMapper objectMapper;

  /** 通过帐号密码登录 */
  @PostMapping("/login")
  public Mono<Object> login(String username, String password, String clientId) {
    Mono<ClientRegistration> reactiveRegistration =
        reactiveClientRegistrationRepository.findByRegistrationId(clientId);
    ClientRegistration registration = reactiveRegistration.block();
    if (registration == null) throw new RuntimeException("appName 错误");
    MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
    map.add("client_id", registration.getClientId());
    map.add("client_secret", registration.getClientSecret());
    map.add("grant_type", "password");
    map.add("username", username);
    map.add("password", password);
    return webClient
        .post()
        .uri(registration.getProviderDetails().getTokenUri(), map)
        .exchange()
        .flatMap((response) -> response.bodyToMono(Object.class));
  }

  // 客户端在拦截的时候 拦截认证token 通过认证token 生成当前客户端的认证token
}
