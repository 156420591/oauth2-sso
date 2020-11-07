package io.lpgph.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Map;


@Slf4j
@AllArgsConstructor
@RestController
public class LoginController {


    private final ObjectMapper objectMapper;

    private final RestTemplate restTemplate;

    /**
     * 其他平台对接自己平台的授权认证模式
     * <p>
     * 如果自己平台之间单点登录的话  客户端和浏览器端还是使用cookie+session的模式
     * <p>
     * http://localhost:8090/oauth/authorize?client_id=login&response_type=code&scope=all&redirect_uri=http://localhost:8085/login/oauth2/code/sys
     */
    @GetMapping("/login/oauth2/code/sys")
    public Object loginCode(String code) throws Exception {
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("code", code);
        map.add("client_id", "login");
        map.add("client_secret", "login");
        map.add("redirect_uri", "http://localhost:8085/login/oauth2/code/sys");
        map.add("grant_type", "authorization_code");
//        Object resp = webClient.post().uri("http://192.168.0.173:8090/oauth/token", map).exchange().flatMap((response) -> response.bodyToMono(Object.class)).block();

//        Map<String, String>resp = restTemplate.postForObject("http://192.168.0.173:8090/oauth/token", map, Map.class);
        ResponseEntity<Map> resp = restTemplate.postForEntity(URI.create("http://192.168.0.173:8090/oauth/token"), map, Map.class);

        String access_token = (String) resp.getBody().get("access_token");
//        String refresh_token = resp.get("refresh_token");
        log.info("\n\n\nHeader\n{}\nToken\n{}\n\n", objectMapper.writeValueAsString(resp.getHeaders()), objectMapper.writeValueAsString(resp.getBody()));

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + access_token);
        HttpEntity<Object> httpEntity = new HttpEntity<>(headers);
        ResponseEntity<String> entity = restTemplate.exchange("http://192.168.0.173:8090/user", HttpMethod.GET, httpEntity, String.class);
        // 授权以后获取用户信息  如果系统未注册则根据用户信息注册  如果已注册 则获取信息进行登录
        log.info("\n\n\nUserInfo\n{}\n\n\n", entity.getBody());

//        HttpHeaders headers2 = new HttpHeaders();
//        headers2.add("Authorization", "Bearer " + access_token);
//        HttpEntity<Object> httpEntity2 = new HttpEntity<>(headers2);
//        log.info("\n\n\nheaders2\n{}\n\n\n", headers2);
//        ResponseEntity<String> rst = restTemplate.exchange("http://localhost:8081/hello", HttpMethod.GET, httpEntity2, String.class);
//        log.info("\n\n\nclient1\n{}\n\n\n", rst.getBody());
        return resp.getBody();
    }

    /**
     * 通过帐号密码登录
     */
    @PostMapping("/login")
    public String login(String username, String password, Model model) throws Exception {
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", "app");
        map.add("client_secret", "app");
        map.add("grant_type", "password");
        map.add("username", username);
        map.add("password", password);
//        Mono<Object> rsp = webClient.post().uri("http://192.168.0.173:8090/oauth/token", map).exchange().flatMap((response) -> response.bodyToMono(Object.class));
        Map<String, String> resp = restTemplate.postForObject("http://192.168.0.173:8090/oauth/token", map, Map.class);

        log.info("\n\n\ntoken\n{}\n\n\n", objectMapper.writeValueAsString(resp));

        model.addAttribute("msg", resp);

        return "index";
    }
}
