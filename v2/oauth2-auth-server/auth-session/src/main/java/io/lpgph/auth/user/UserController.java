package io.lpgph.auth.user;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@Slf4j
@RestController
public class UserController {

  @GetMapping("/user")
  public Principal user(Principal principal) {
    return principal;
  }



}
