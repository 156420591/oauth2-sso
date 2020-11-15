package io.lpgph.auth.oauth2.filter;

import io.lpgph.auth.common.json.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class JwtAuthenticationTokenFilter extends BasicAuthenticationFilter {

  public JwtAuthenticationTokenFilter(AuthenticationManager authenticationManager) {
    super(authenticationManager);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    log.info(
        "\n\n当前请求 {}\naccess_token\n  {}\nAuthorization\n  {}\ntest\n  {}\n\n",
        request.getRequestURI(),
        JsonUtil.toJson(request.getHeader("access_token")),
        JsonUtil.toJson(request.getHeader("Authorization")),
        JsonUtil.toJson(request.getHeader("test")));
    filterChain.doFilter(request, response);
  }
}
