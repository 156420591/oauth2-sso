package io.lpgph.res.product;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.AntPathMatcher;

@Slf4j
@SpringBootTest
class GoodsApplicationTests {

  @Test
  void contextLoads() {
    AntPathMatcher antPathMatcher = new AntPathMatcher();
    log.info("/login  /**  {}", antPathMatcher.match( "/**","/login"));
    AntPathRequestMatcher antPathMatcher2 = new AntPathRequestMatcher("*");
  }
}
