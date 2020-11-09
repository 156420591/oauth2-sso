package io.lpgph.client;

import lombok.AllArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@AllArgsConstructor
@RestController
public class HelloController {

  private final ReactiveClientRegistrationRepository reactiveClientRegistrationRepository;

  private final WebClient webClient;

  @GetMapping("/hello")
  public String index(
      Model model,
      @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
      @AuthenticationPrincipal OAuth2User oauth2User) {
    model.addAttribute("userName", oauth2User.getName());
    model.addAttribute("clientName", authorizedClient.getClientRegistration().getClientName());
    model.addAttribute("userAttributes", oauth2User.getAttributes());
    return "index";
  }


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
}
