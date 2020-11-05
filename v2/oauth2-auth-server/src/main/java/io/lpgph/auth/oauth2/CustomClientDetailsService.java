package io.lpgph.auth.oauth2;

import io.lpgph.auth.common.bean.RESTfulGrantedAuthority;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;

@Slf4j
@Service
public class CustomClientDetailsService implements ClientDetailsService {

  @Autowired private PasswordEncoder passwordEncoder;

  @Override
  public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
    BaseClientDetails clientDetails = new BaseClientDetails();

    switch (clientId) {
      case "login":
        clientDetails.setClientId("login");
        clientDetails.setClientSecret(passwordEncoder.encode("login"));
        clientDetails.setAuthorizedGrantTypes(List.of("authorization_code", "refresh_token"));
        clientDetails.setAutoApproveScopes(List.of("all")); // 自动授权的scope
        clientDetails.setScope(List.of("all"));
        // 授权模式 认证成功够跳转跳转页面 并携带授权码
        clientDetails.setRegisteredRedirectUri(
            Set.of(
                "http://localhost:8080/login/oauth2/code/login-client",
                "http://localhost:8082/login/oauth2/code/login-client"));
        break;
      case "test":
        clientDetails.setClientId("test");
        clientDetails.setClientSecret(passwordEncoder.encode("test"));
        clientDetails.setAuthorizedGrantTypes(List.of("authorization_code", "refresh_token"));
        clientDetails.setScope(List.of("all"));
        // 授权模式 认证成功够跳转跳转页面 并携带授权码
        clientDetails.setRegisteredRedirectUri(
            Set.of(
                "http://localhost:8080/login/oauth2/code/login-client",
                "http://localhost:8082/login/oauth2/code/login-client"));
        break;
      case "app":
        clientDetails.setClientId("app");
        clientDetails.setClientSecret(passwordEncoder.encode("app"));
        clientDetails.setAuthorizedGrantTypes(List.of("password", "refresh_token"));
        clientDetails.setAutoApproveScopes(List.of("all"));
        clientDetails.setScope(List.of("all"));
        clientDetails.setAuthorities(
            List.of(
                new RESTfulGrantedAuthority("/a", "GET"),
                new RESTfulGrantedAuthority("/b", "POST"),
                new RESTfulGrantedAuthority("/c", "GET")));
        break;
      case "user":
        clientDetails.setClientId("user");
        clientDetails.setClientSecret(passwordEncoder.encode("user"));
        clientDetails.setAuthorizedGrantTypes(List.of("client_credentials", "refresh_token"));
        clientDetails.setAccessTokenValiditySeconds(60 * 60 * 24 * 30);
        clientDetails.setRefreshTokenValiditySeconds(60 * 60 * 24 * 180);
        clientDetails.setAutoApproveScopes(List.of("read", "write"));
        clientDetails.setAuthorities(List.of(new RESTfulGrantedAuthority("/**", "ALL")));
        clientDetails.setScope(List.of("read", "write", "user:write"));
        break;
      default:
        clientDetails.setClientId("order");
        clientDetails.setClientSecret(passwordEncoder.encode("order"));
        clientDetails.setAuthorizedGrantTypes(List.of("client_credentials", "refresh_token"));
        clientDetails.setAccessTokenValiditySeconds(60 * 60 * 24 * 30);
        clientDetails.setRefreshTokenValiditySeconds(60 * 60 * 24 * 180);
        clientDetails.setAutoApproveScopes(List.of("read", "write"));
        clientDetails.setAuthorities(List.of(new RESTfulGrantedAuthority("/**", "**")));
        clientDetails.setScope(List.of("read", "write", "order:write"));
    }

    return clientDetails;
  }
}
