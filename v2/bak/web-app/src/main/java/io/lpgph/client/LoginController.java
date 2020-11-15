package io.lpgph.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.function.ServerResponse;

import java.net.URI;
import java.net.http.HttpResponse;
import java.util.Map;

@Slf4j
@RestController
public class LoginController {

  @Autowired private ObjectMapper objectMapper;

  @Autowired private RestTemplate restTemplate;

  /** 通过帐号密码登录 */
  @PostMapping("/login")
  public Object login(String username, String password) throws Exception {
    MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
    map.add("client_id", "app");
    map.add("client_secret", "app");
    map.add("grant_type", "password");
    map.add("username", username);
    map.add("password", password);
    //        Mono<Object> rsp = webClient.post().uri("http://192.168.0.173:8090/oauth/token",
    // map).exchange().flatMap((response) -> response.bodyToMono(Object.class));
    Map<String, String> resp =
        restTemplate.postForObject("http://192.168.0.173:8090/oauth/token", map, Map.class);
    log.info("\n\n\nresp\n{}\n\n\n", objectMapper.writeValueAsString(resp));
    //        model.addAttribute("msg", resp);
    return resp.get("access_token");
  }

  /** 通过帐号密码登录 */
  @PostMapping("/login2")
  public void login2(String username, String password) throws Exception {
    MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
    map.add("username", username);
    map.add("password", password);
    ResponseEntity<Map> resp =
        restTemplate.postForEntity("http://192.168.0.173:8090/login", map, Map.class);
    log.info("\n\n\nresp\n{}\n\n\n", objectMapper.writeValueAsString(resp));

    HttpHeaders headers = new HttpHeaders();
    headers.add("X-Auth-Token", resp.getHeaders().getFirst("X-Auth-Token"));

    MultiValueMap<String, String> authMap = new LinkedMultiValueMap<>();
    authMap.add("client_id", "client1");
    authMap.add("response_type", "code");
    authMap.add("redirect_uri", "http://localhost:8085/login/oauth2/code/sys");

    HttpEntity<Object> httpEntity = new HttpEntity<>(authMap, headers);
    log.info("\n\n\nhttpEntity \n{}\n\n\n", objectMapper.writeValueAsString(httpEntity));
    ResponseEntity<Map> entity =
        restTemplate.exchange(
            "http://192.168.0.173:8090/oauth/authorize", HttpMethod.POST, httpEntity, Map.class);

    // 授权以后获取用户信息  如果系统未注册则根据用户信息注册  如果已注册 则获取信息进行登录
    log.info("获取授权后的返回信息 {}", objectMapper.writeValueAsString(entity));
  }

  /**
   * 其他平台对接自己平台的授权认证模式
   *
   * <p>如果自己平台之间单点登录的话 客户端和浏览器端还是使用cookie+session的模式
   *
   * <p>code传递到前端页面后 前端通过code请求后台获取认证token 生成token后将token
   *
   * <p>http://localhost:8090/oauth/authorize?client_id=login&response_type=code&scope=all&redirect_uri=http://localhost:8085/login/oauth2/code/sys
   */
  @GetMapping("/login/oauth2/code/sys")
  public Object loginCode(String code) throws Exception {

    log.info("\n\n\n转发过来的code  {}\n\n\n", code);

    MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
    map.add("code", code);
    map.add("client_id", "client1");
    map.add("client_secret", "client1");
    map.add("redirect_uri", "http://localhost:8085/login/oauth2/code/sys");
    map.add("grant_type", "authorization_code");
    //        Object resp = webClient.post().uri("http://192.168.0.173:8090/oauth/token",
    // map).exchange().flatMap((response) -> response.bodyToMono(Object.class)).block();

    //        Map<String, String>resp =
    // restTemplate.postForObject("http://192.168.0.173:8090/oauth/token", map, Map.class);
    ResponseEntity<Map> resp =
        restTemplate.postForEntity(
            URI.create("http://192.168.0.173:8090/oauth/token"), map, Map.class);

    log.info("\n\n\n 客户端认证信息 \n{}\n\n", objectMapper.writeValueAsString(resp));

    String access_token = (String) resp.getBody().get("access_token");
    //        String refresh_token = resp.get("refresh_token");
    log.info("\n\n\naccess_token {}\n\n\n", access_token);
    HttpHeaders headers = new HttpHeaders();
    headers.add("Authorization", "Bearer " + access_token);

    HttpEntity<Object> httpEntity = new HttpEntity<>(headers);
    ResponseEntity<String> entity =
        restTemplate.exchange(
            "http://192.168.0.173:8090/user", HttpMethod.GET, httpEntity, String.class);
    // 授权以后获取用户信息  如果系统未注册则根据用户信息注册  如果已注册 则获取信息进行登录
    log.info("\n\n\nUserInfo\n{}\n\n\n", entity.getBody());
    return resp.getBody();
  }

  // https://login.m.taobao.com/newlogin/login.do?appName=taobao&fromSite=0
  // https://login.taobao.com/newlogin/login.do?appName=taobao&fromSite=0

  //  @GetMapping("/test")
  //  public void loginClient(ServerResponse response,@RequestHeader("Authorization") String auth)
  // throws Exception {
  //    response.writeTo()
  //  }
  //
  //  /**
  //   * 通过认证token访问第三放资源 自动授权
  //   *
  //   * @param auth
  //   * @throws Exception
  //   */
  //  @GetMapping("/login/c1")
  //  public void loginClient(@RequestHeader("Authorization") String auth) throws Exception {
  //    log.info("\n\n\nAuthorization\n{}\n\n\n", auth);
  //    HttpHeaders headers = new HttpHeaders();
  //    headers.add("Authorization", auth);
  //    headers.add("test", auth);
  //    //    headers.add("Authorization", "Bearer " + auth);
  //    HttpEntity<Object> httpEntity = new HttpEntity<>(headers);
  //    log.info("\n\n\nhttpEntity\n{}\n\n\n", httpEntity);
  //    ResponseEntity<String> rst =
  //        restTemplate.exchange(
  //            "http://localhost:8082/hello", HttpMethod.GET, httpEntity, String.class);
  //    log.info("\n\n\nclient1\n{}\n\n\n", rst);
  //  }
  //
  //  /**
  //   * 获取授权码授权
  //   *
  //   * @param accessToken
  //   * @throws Exception
  //   */
  //  @GetMapping("/login/c2")
  //  public void loginClient2(@RequestHeader("Authorization") String accessToken) throws Exception
  // {
  //    log.info("\n\n\naccess_token\n{}\n\n\n", accessToken);
  //
  //    HttpHeaders headers = new HttpHeaders();
  //    headers.add("Authorization", "Bearer " + accessToken);
  //    headers.add("test", "tttttttt");
  //
  //    MultiValueMap<String, String> authMap = new LinkedMultiValueMap<>();
  //    authMap.add("client_id", "client1");
  //    authMap.add("response_type", "code");
  //    authMap.add("redirect_uri", "http://localhost:8085/login/oauth2/code/sys");
  //
  //    HttpEntity<Object> httpEntity = new HttpEntity<>(authMap, headers);
  //    log.info("\n\n\nhttpEntity \n{}\n\n\n", objectMapper.writeValueAsString(httpEntity));
  //    ResponseEntity<Map> entity =
  //        restTemplate.exchange(
  //            "http://192.168.0.173:8090/oauth/authorize", HttpMethod.POST, httpEntity,
  // Map.class);
  //
  //    log.info("获取授权后的token {}", objectMapper.writeValueAsString(entity));
  //  }

}
