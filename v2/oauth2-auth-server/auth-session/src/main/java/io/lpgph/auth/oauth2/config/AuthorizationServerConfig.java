package io.lpgph.auth.oauth2.config;

import io.lpgph.auth.oauth2.enhancer.CustomTokenEnhancer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.*;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.Arrays;

/**
 * @see
 *     org.springframework.boot.autoconfigure.security.oauth2.authserver.OAuth2AuthorizationServerConfiguration;
 */
@Slf4j
@EnableAuthorizationServer
@Configuration
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

  @Autowired private AuthenticationManager authenticationManager;

  @Autowired private UserDetailsService customUserDetailsService;

  @Autowired private ClientDetailsService customClientDetailsService;

  //  @Autowired private AuthorizationServerTokenServices jwtTokenServices;

  @Autowired private TokenStore tokenStore;

  @Autowired private JwtAccessTokenConverter accessTokenConverter;

  @Autowired private PasswordEncoder passwordEncoder;

  /**
   * 授权端点开放
   *
   * @param security
   */
  @Override
  public void configure(AuthorizationServerSecurityConfigurer security) {
    security
        .passwordEncoder(passwordEncoder)
        // 开启/oauth/token_key  验证端口认证权限访问
        .tokenKeyAccess("permitAll()")
        // 开启/oauth/check_token 验证端口无权限访问
        //                .checkTokenAccess("isAuthenticated()")
        .checkTokenAccess("permitAll()")
        //                .passwordEncoder(passwordEncoder)  //设置oauth_client_details中的密码编码器
        // 支持客户端表单认证
        .allowFormAuthenticationForClients();
  }

  /**
   * 用来配置客户端详情服务（ClientDetailsService），客户端详情信息在这里进行初始化，你能够把客户端详情信息写死在这里或者是通过数据库来存储调取详情信息
   *
   * @param clients
   * @param clients
   * @throws Exception
   */
  @Override
  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    clients.withClientDetails(customClientDetailsService);
  }

  /**
   * 配置身份认证器，配置认证方式，TokenStore，TokenGranter，OAuth2RequestFactory
   *
   * @param endpoints
   */
  @Override
  public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

    // 设置jwt签名和jwt增强器到TokenEnhancerChain
    TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
    tokenEnhancerChain.setTokenEnhancers(
        Arrays.asList(accessTokenConverter, new CustomTokenEnhancer()));
    endpoints
        .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST)
        .authenticationManager(authenticationManager) // 密码授权模式需要
        //        .tokenServices(jwtTokenServices)    // 如果使用默认tokenServices 则启用下面三个
        .tokenStore(tokenStore) // 在jwt和oauth2服务器之间充当翻译（签名）
        .tokenEnhancer(tokenEnhancerChain) // 令牌增强器类：扩展jwt token
        .accessTokenConverter(accessTokenConverter) // 配置令牌生成
        .reuseRefreshTokens(false) // 刷新token是否重复使用
        .userDetailsService(customUserDetailsService); // 刷新令牌需要

    //                .pathMapping("/oauth/token", "/login")  // 替换url
    //                .pathMapping("/oauth/authorize", "/authorize")  // 替换url

  }
}
