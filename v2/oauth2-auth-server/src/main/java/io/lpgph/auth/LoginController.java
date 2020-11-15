package io.lpgph.auth;

import io.lpgph.auth.common.json.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@RestController
public class LoginController {

  @Autowired private AuthenticationManager authenticationManager;

  @Autowired private ClientDetailsService customClientDetailsService;

  @Autowired private AuthorizationServerTokenServices jwtTokenServices;

  private final OAuth2RequestFactory oAuth2RequestFactory =
      new DefaultOAuth2RequestFactory(customClientDetailsService);

  /** 通过帐号密码登录 */
  @PostMapping("/login/new")
  public Object login(
      String username, String password, @RequestParam("client_id") String clientId) {
    log.info("");

    ClientDetails clientDetails = customClientDetailsService.loadClientByClientId(clientId);
    Map<String, String> map = new HashMap<>();
    map.put("username", username);
    map.put("password", password);
    map.put("grant_type", "password");

    TokenRequest tokenRequest = oAuth2RequestFactory.createTokenRequest(map, clientDetails);
    Map<String, String> parameters = new LinkedHashMap<>(tokenRequest.getRequestParameters());
    Authentication userAuth = new UsernamePasswordAuthenticationToken(username, password);
    ((AbstractAuthenticationToken) userAuth).setDetails(parameters);
    try {
      userAuth = authenticationManager.authenticate(userAuth);
    } catch (AccountStatusException | BadCredentialsException ase) {
      throw new InvalidGrantException(ase.getMessage());
    }
    if (userAuth == null || !userAuth.isAuthenticated()) {
      throw new InvalidGrantException("Could not authenticate user: " + username);
    }
    OAuth2Request storedOAuth2Request =
        oAuth2RequestFactory.createOAuth2Request(clientDetails, tokenRequest);
    OAuth2Authentication oAuth2Authentication =
        new OAuth2Authentication(storedOAuth2Request, userAuth);

    log.info("\n\n登录成功 OAuth2AccessToken\n{}\n\n", JsonUtil.toJson(oAuth2Authentication));
    return jwtTokenServices.createAccessToken(oAuth2Authentication);
  }
}
