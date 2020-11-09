package io.lpgph.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
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
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;


@Slf4j
@AllArgsConstructor
@RestController
public class HelloController {

    private final ObjectMapper objectMapper;

    private final ReactiveClientRegistrationRepository reactiveClientRegistrationRepository;

    private final WebClient webClient;

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


    @GetMapping("/hello")
    public String hello(
            @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
            @AuthenticationPrincipal OAuth2User oauth2User) throws Exception {
        log.info("\n\n\nclient\n{}\n\n\n", objectMapper.writeValueAsString(authorizedClient));
        log.info("\n\n\nOAuth2User\n{}\n\n\n", objectMapper.writeValueAsString(oauth2User));
        return "hello";
    }



    /** 通过帐号密码登录 */
    @PostMapping("/login")
    public void login(ServerRequest request, ServerResponse response, String username, String password, String clientId) {
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

       Object object =  webClient
                .post()
                .uri(registration.getProviderDetails().getTokenUri(), map)
                .exchange()
                .flatMap((rsp) -> rsp.bodyToMono(Object.class)).block();

       //         response.cookies().keySet()

    }

}
