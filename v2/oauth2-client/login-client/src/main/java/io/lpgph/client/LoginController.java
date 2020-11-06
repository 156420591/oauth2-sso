package io.lpgph.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
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

    /**
     * 自己平台认证
     * http://localhost:8090/oauth/authorize?client_id=login&response_type=code&scope=all&redirect_uri=http://localhost:8085/login/oauth2/code/sys
     */
    @GetMapping("/login/oauth2/code/sys")
    public Object loginCode(String code) {
        ClientRegistration registration = reactiveClientRegistrationRepository.findByRegistrationId("auth-login").block();
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("code", code);
        map.add("client_id", registration.getClientId());
        map.add("client_secret", registration.getClientSecret());
        map.add("redirect_uri", registration.getRedirectUriTemplate());
        map.add("grant_type", registration.getAuthorizationGrantType().getValue());
        Object objectMono =  webClient.post().uri(registration.getProviderDetails().getTokenUri(), map).exchange().flatMap((response) -> response.bodyToMono(Object.class)).block();
        try {
            log.info("\n\n\ntoken\n{}\n\n\n",objectMapper.writeValueAsString(objectMono));
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return objectMono;
    }


//    /**
//     * 微信平台认证
//     */
//    @GetMapping("/login/oauth2/code/wx")
//    public String WxLoginCode(String code, Model model) {
//        String access_token = "";
//        String refresh_token = "";
//
//        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
//        map.add("code", code);
//        map.add("client_id", "login");
//        map.add("client_secret", "login");
//        map.add("redirect_uri", "http://localhost:8089/index.html");
//        map.add("grant_type", "authorization_code");
//
//        Map<String, String> resp = restTemplate.postForObject("http://localhost:8090/oauth/token", map, Map.class);
//
////            return Mono.defer(() -> this.webClient.post()
////                    .uri(clientRegistration(grantRequest).getProviderDetails().getTokenUri())
////                    .headers((headers) -> populateTokenRequestHeaders(grantRequest, headers))
////                    .body(createTokenRequestBody(grantRequest))
////                    .exchange()
////                    .flatMap((response) -> readTokenResponse(grantRequest, response))
////            );
//
//        System.out.println(resp);
//        access_token = resp.get("access_token");
//        refresh_token = resp.get("refresh_token");
//
//        // 获取到token以后  检测用户是否已注册  如果已注册则根据 openId和密钥 通过帐号密码登录的方式认证 获取token
//        // 如果没有注册  则获取用户微信信息 openId 密钥 创建本地用户 信息 然后通过帐号密码的方式进行认证返回token
//        try {
//            HttpHeaders headers = new HttpHeaders();
//            headers.add("Authorization", "Bearer " + access_token);
//            HttpEntity<Object> httpEntity = new HttpEntity<>(headers);
//            ResponseEntity<String> entity = restTemplate.exchange("http://localhost:8084/hello", HttpMethod.GET, httpEntity, String.class);
//            return entity.getBody();
//        } catch (RestClientException e) {
//            return "未加载";
//        }
//    }

    /**
     * 通过帐号密码登录
     */
    @PostMapping("/login")
    public Mono<Object> login(String username, String password) {
        ClientRegistration registration = reactiveClientRegistrationRepository.findByRegistrationId("login").block();
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", registration.getClientId());
        map.add("client_secret", registration.getClientSecret());
        map.add("grant_type", registration.getAuthorizationGrantType().getValue());
        map.add("username", username);
        map.add("password", password);
        return webClient.post().uri(registration.getProviderDetails().getTokenUri(), map).exchange().flatMap((response) -> response.bodyToMono(Object.class));
    }
}
