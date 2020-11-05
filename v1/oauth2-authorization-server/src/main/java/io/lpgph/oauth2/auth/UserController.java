package io.lpgph.oauth2.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@Slf4j
@RestController
public class UserController {

  @Autowired private ObjectMapper objectMapper;

  @GetMapping("/user")
  public Principal user(Principal principal) throws Exception {
    log.info("\n\n user {} \n\n", objectMapper.writeValueAsString(principal));
    return principal;
  }
}
