package io.lpgph.res.product;

import io.lpgph.res.product.json.JsonUtil;
import io.lpgph.res.product.rpc.IOrderService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.UUID;

@Slf4j
@AllArgsConstructor
@RestController
@RequestMapping
public class ProductController {

  @Autowired private IOrderService orderService;

  @GetMapping("/hello")
  public String hello() {
    return "goods " + UUID.randomUUID().toString();
  }

  @GetMapping("/info")
  public Object info(Principal principal) {
    log.info("\n\n\n\n info  {}\n\n\n\n", JsonUtil.toJson(principal));
    return principal;
  }

  @GetMapping("/show")
  public String test() {
    return orderService.showMsg();
  }

  //  @GetMapping("/show1")
  //  public String index(@AuthenticationPrincipal Jwt jwt) {
  //    log.info("\n\n show1  {}\n\n", JsonUtil.toJson(jwt));
  //    return String.format("Hello, %s!", JsonUtil.toJson(jwt.getClaims()));
  //  }

  @GetMapping("/show2")
  public String index(@AuthenticationPrincipal Object object) {
    log.info("\n\n show1  {}\n\n", JsonUtil.toJson(object));
    return String.format("Hello, %s!", JsonUtil.toJson(object));
  }

  @GetMapping("/show3")
  public Object show4(Authentication authentication) {
    log.info("\n\n authentication  {}\n\n", JsonUtil.toJson(authentication));
    return authentication;
  }

  @GetMapping("/show4")
  public Object show4(Principal principal) {
    log.info("\n\n authentication  {}\n\n", JsonUtil.toJson(principal));
    return principal;
  }

  @GetMapping("/show5")
  public String show5(@AuthenticationPrincipal(expression = "#this.claims.userId") long userId) {
    log.info("\n\n show1  {}\n\n", userId);
    return String.format("Hello, %s!", userId);
  }

  @GetMapping("/show6")
  public Object show6(ServerHttpRequest request, Authentication authentication) {
    log.info("\n\n header  {}\n\n", JsonUtil.toJson(request.getHeaders()));
    log.info("\n\n authentication  {}\n\n", JsonUtil.toJson(authentication));
    return authentication;
  }
}
