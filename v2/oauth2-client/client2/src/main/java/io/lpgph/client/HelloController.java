package io.lpgph.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.server.HttpServerRequest;
import reactor.netty.http.server.HttpServerResponse;

@Slf4j
@AllArgsConstructor
@RestController
public class HelloController {

  private final ReactiveClientRegistrationRepository reactiveClientRegistrationRepository;

  private final WebClient webClient;

  private final ObjectMapper objectMapper;

  @Autowired private ReactiveOAuth2AuthorizedClientManager authorizedClientManager;

  @GetMapping("/auth")
  public Object auth(Authentication authentication) throws Exception {
    log.info("\nAuthentication {}\n", objectMapper.writeValueAsString(authentication));
    return authentication;
  }

  @GetMapping("/auth/hello")
  public String hello(
      Authentication authentication,
      HttpServerRequest serverRequest,
      HttpServerResponse serverResponse)
      throws Exception {
    log.info("\nAuthentication {}\n", objectMapper.writeValueAsString(authentication));
    //    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication != null) {
      OAuth2AuthorizeRequest authorizeRequest =
          OAuth2AuthorizeRequest.withClientRegistrationId("login-client")
              .principal(authentication)
              .attributes(
                  attrs -> {
                    attrs.put(HttpServerRequest.class.getName(), serverRequest);
                    attrs.put(HttpServerResponse.class.getName(), serverResponse);
                  })
              .build();
      OAuth2AuthorizedClient authorizedClient =
          this.authorizedClientManager.authorize(authorizeRequest).block();
      OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
      log.info("accessToken  {} ", objectMapper.writeValueAsString(accessToken));
    }
    return "index";
  }

  @GetMapping("/")
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
  //  @PostMapping("/login")
  //  public Mono<Object> login(String username, String password, String clientId) {
  //    Mono<ClientRegistration> reactiveRegistration =
  //        reactiveClientRegistrationRepository.findByRegistrationId(clientId);
  //    ClientRegistration registration = reactiveRegistration.block();
  //    if (registration == null) throw new RuntimeException("appName 错误");
  //    MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
  //    map.add("client_id", registration.getClientId());
  //    map.add("client_secret", registration.getClientSecret());
  //    map.add("grant_type", "password");
  //    map.add("username", username);
  //    map.add("password", password);
  //    return webClient
  //        .post()
  //        .uri(registration.getProviderDetails().getTokenUri(), map)
  //        .exchange()
  //        .flatMap((response) -> response.bodyToMono(Object.class));
  //  }
}
