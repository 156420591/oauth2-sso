package io.lpgph.auth.user;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@Slf4j
@RestController
public class UserController {

  @GetMapping("/")
  public Principal index(Principal principal) {
    return principal;
  }

  @GetMapping("/user")
  public Principal user(Principal principal) {
    return principal;
  }

  @GetMapping("/test")
  public Principal test(Principal principal) {
    return principal;
  }
}
