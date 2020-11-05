package io.lpgph.auth.oauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.bootstrap.encrypt.KeyProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.security.KeyPair;

@Configuration
public class TokenConfig {

  @Autowired private KeyProperties keyProperties;

  /**
   * 是用来生成token的转换器，而token令牌默认是有签名的，且资源服务器需要验证这个签名。加密及验签包括两种方式： 对称加密、非对称加密（公钥密钥） 此处使用非对称加密
   *
   * @return
   */
  @Bean
  public JwtAccessTokenConverter accessTokenConverter() {
    /*
     * 通过 JDK 工具生成 JKS 证书文件，并将 keystore.jks 放入resource目录下
     * keytool -genkeypair -alias test -keyalg RSA -dname "CN=Web Server,OU=lpgph,O=lpgph.github.io,L=BeiJing,S=BeiJing,C=CN" -keypass testpass -storetype PKCS12 -keystore ./test.p12 -storepass testpass
     * // P12 生成jks
     * keytool -importkeystore -srckeystore keystore.p12 -srcstoretype PKCS12 -deststoretype JKS -destkeystore keystore.jks
     * // jsk转P12
     * keytool -importkeystore -srckeystore keystore.jks -srcstoretype JKS -deststoretype PKCS12 -destkeystore keystore.p12
     * // 生成证书
     * keytool -export -alias test -keystore ./test.jks  -storetype PKCS12 -storepass testpass -rfc -file ./test.cer
     * // 生成公钥和证书
     * keytool -list -rfc --keystore ./test.jks| openssl x509 -inform pem -pubkey
     * */
    KeyPair keyPair =
        new KeyStoreKeyFactory(
                keyProperties.getKeyStore().getLocation(),
                keyProperties.getKeyStore().getPassword().toCharArray())
            .getKeyPair(keyProperties.getKeyStore().getAlias());
    JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
    converter.setKeyPair(keyPair);
    return converter;
  }

  @Bean
  public TokenStore tokenStore() {
    return new JwtTokenStore(accessTokenConverter());
  }

  //  @Bean
  //  public DefaultTokenServices jwtTokenServices(TokenStore tokenStore) {
  //    DefaultTokenServices services = new DefaultTokenServices();
  //    services.setClientDetailsService(customClientDetailsService);
  //    services.setSupportRefreshToken(true);
  //    //    services.setReuseRefreshToken(false);
  //    services.setTokenStore(tokenStore);
  //    services.setAccessTokenValiditySeconds(60 * 5);
  //    services.setRefreshTokenValiditySeconds(60 * 10);
  //    // 自定义token过滤链
  //    TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
  //    tokenEnhancerChain.setTokenEnhancers(
  //        Arrays.asList(accessTokenConverter(), new CustomTokenEnhancer()));
  //    services.setTokenEnhancer(tokenEnhancerChain);
  //    return services;
  //  }
}
