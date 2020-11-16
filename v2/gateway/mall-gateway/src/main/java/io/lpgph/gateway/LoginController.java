package io.lpgph.gateway;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactivePasswordTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Slf4j
@AllArgsConstructor
@RestController
public class LoginController {

  private final ObjectMapper objectMapper;

  private final ReactiveClientRegistrationRepository reactiveClientRegistrationRepository;

  //  @GetMapping("/")
  //  public String index(
  //      Model model,
  //      @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
  //      @AuthenticationPrincipal OAuth2User oauth2User) {
  //    model.addAttribute("userName", oauth2User.getName());
  //    model.addAttribute("clientName", authorizedClient.getClientRegistration().getClientName());
  //    model.addAttribute("userAttributes", oauth2User.getAttributes());
  //    return "index";
  //  }
  //
  //  @Autowired private ReactiveOAuth2AuthorizedClientManager authorizedClientManager;

  @PostMapping("/login/t1")
  public Object t1() {
    return "tttttt";
  }

  @PostMapping("/login/t2")
  public Object t2(String appId) {
    return reactiveClientRegistrationRepository.findByRegistrationId(appId);
  }

  private ServerSecurityContextRepository securityContextRepository =
      new WebSessionServerSecurityContextRepository();

  @PostMapping("/login")
  public Object login(LoginInfo loginInfo) throws JsonProcessingException {
    ClientRegistration registration =
        reactiveClientRegistrationRepository.findByRegistrationId(loginInfo.getAppId()).block();
    if (registration == null) throw new RuntimeException("registration not null!!!");
    ReactiveOAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient =
        new WebClientReactivePasswordTokenResponseClient();
    //    return accessTokenResponseClient.getTokenResponse(
    //            new OAuth2PasswordGrantRequest(
    //                    registration, loginInfo.getUsername(), loginInfo.getPassword()));
    Mono<OAuth2AccessTokenResponse> rps =
        accessTokenResponseClient.getTokenResponse(
            new OAuth2PasswordGrantRequest(
                registration, loginInfo.getUsername(), loginInfo.getPassword()));
    log.info(
        "OAuth2AccessTokenResponse  {} ",
        objectMapper.writeValueAsString(rps.block(Duration.ofSeconds(10))));
    return rps;
  }

//  @PostMapping("/login2")
//  public String index(
//      Authentication authentication,
//      HttpServerRequest serverRequest,
//      HttpServerResponse serverResponse)
//      throws Exception {
//    //    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//    if (authentication != null) {
//      OAuth2AuthorizeRequest authorizeRequest =
//          OAuth2AuthorizeRequest.withClientRegistrationId("login-client")
//              .principal(authentication)
//              .attributes(
//                  attrs -> {
//                    attrs.put(HttpServerRequest.class.getName(), serverRequest);
//                    attrs.put(HttpServerResponse.class.getName(), serverResponse);
//                  })
//              .build();
//      OAuth2AuthorizedClient authorizedClient =
//          this.authorizedClientManager.authorize(authorizeRequest).block();
//      OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
//      log.info("accessToken  {} ", objectMapper.writeValueAsString(accessToken));
//    }
//    return "index";
//  }
}
