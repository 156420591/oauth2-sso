package io.lpgph.res.order;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.UUID;

@Slf4j
@RestController
public class OrderController {

  @GetMapping("/hello")
  public String hello() {
    return "order hello" + UUID.randomUUID().toString();
  }

  @GetMapping("/role")
  public String role() {
    return "order role" + UUID.randomUUID().toString();
  }

  @GetMapping("/auth")
  public String auth() {
    return "order auth" + UUID.randomUUID().toString();
  }
}
