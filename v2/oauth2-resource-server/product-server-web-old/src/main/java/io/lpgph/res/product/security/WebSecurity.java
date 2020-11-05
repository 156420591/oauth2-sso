package io.lpgph.res.product.security;

import io.lpgph.res.product.json.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.util.AntPathMatcher;

import javax.servlet.http.HttpServletRequest;

/**
 * see https://docs.spring.io/spring-security/site/docs/5.4.1/reference/html5/#el-access-web-beans
 */
@Slf4j
public class WebSecurity {

  private static final AntPathMatcher antPathMatcher = new AntPathMatcher();

  public boolean check(Authentication authentication, HttpServletRequest request) {
    if (authentication == null) return false;
    String uri = request.getContextPath();
    String method = request.getMethod();
    String authority = uri + ":" + method;
    log.info("\n\n\nAuthentication\n{}\n\n\n", JsonUtil.toJson(authentication));
    if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
      return authentication.getAuthorities().stream()
          .anyMatch(a -> antPathMatcher.match(a.getAuthority(), authority));
    }
    return false;
  }
}
