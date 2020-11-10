package io.lpgph.auth.oauth2.filter;

import io.lpgph.auth.common.json.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.connector.RequestFacade;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @see
 *     org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter
 *     <p>// * GenericFilterBean
 *     OncePerRequestFilter 一次请求只通过一次filter，而不需要重复执行
 */
@Slf4j
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

  private final TokenStore tokenStore;

  private final TokenExtractor tokenExtractor;

  public JwtAuthenticationTokenFilter(TokenStore tokenStore) {
    this.tokenStore = tokenStore;
    this.tokenExtractor = new BearerTokenExtractor();
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    log.info(
        "\n\n当前请求头部内容 {}\n\n\n  {} \n\n\n", JsonUtil.toJson(request.getHeaderNames()),JsonUtil.toJson(request.getHeader("Authorization")));

    Authentication authentication = tokenExtractor.extract(request);
    if (authentication != null && authentication.getPrincipal() != null) {
      try {
        // 截取JWT前缀
        String token = (String) authentication.getPrincipal();
        OAuth2Authentication auth2Authentication = tokenStore.readAuthentication(token);
        log.info(
            "\n\n\njwtTokenStore.readAuthentication\n{}\n\n\n",
            JsonUtil.toJson(auth2Authentication));
        SecurityContextHolder.getContext().setAuthentication(auth2Authentication);
      } catch (Exception e) {
        log.info("Token无效");
      }
    }
    filterChain.doFilter(request, response);
  }
}
