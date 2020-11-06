package io.lpgph.auth.oauth2.handler;

import io.lpgph.auth.common.json.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;

/** 帐号登录成功后使用password进行授权 */
@Slf4j
@Component
public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

  @Autowired private ClientDetailsService customClientDetailsService;

  @Autowired private PasswordEncoder passwordEncoder;

  @Autowired private AuthorizationServerTokenServices jwtTokenServices;

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {
    // 系统内部登录  默认使用password进行授权
    //        String type = request.getHeader("Accept");
    //        if (!type.contains("text/html")) {
    log.info("\n\n登录成功 Authentication\n{}\n\n", JsonUtil.toJson(authentication));
    String clientId = "app";
    String clientSecret = "app";

    ClientDetails clientDetails = customClientDetailsService.loadClientByClientId(clientId);
    if (null == clientDetails) {
      throw new UnapprovedClientAuthenticationException("clientId不存在" + clientId);
    } else if (!passwordEncoder.matches(clientSecret, clientDetails.getClientSecret())) {
      throw new UnapprovedClientAuthenticationException("clientSecret不匹配" + clientId);
    }
    TokenRequest tokenRequest =
        new TokenRequest(new HashMap<>(), clientId, clientDetails.getScope(), "password");
    OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);
    log.info("\n\n登录成功 OAuth2Request\n{}\n\n", JsonUtil.toJson(oAuth2Request));
    OAuth2Authentication oAuth2Authentication =
        new OAuth2Authentication(oAuth2Request, authentication);
    log.info("\n\n登录成功 OAuth2Authentication\n{}\n\n", JsonUtil.toJson(oAuth2Authentication));
    OAuth2AccessToken token = jwtTokenServices.createAccessToken(oAuth2Authentication);
    log.info("\n\n登录成功 OAuth2AccessToken\n{}\n\n", JsonUtil.toJson(token));
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.getWriter().write(JsonUtil.toJson(token));
  }
}
