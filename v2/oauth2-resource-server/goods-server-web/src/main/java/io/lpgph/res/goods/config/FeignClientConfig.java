package io.lpgph.res.goods.config;

import io.lpgph.res.goods.config.feign.OAuth2FeignRequestInterceptor;
import feign.Logger;
import feign.RequestInterceptor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.oauth2.client.ClientsConfiguredCondition;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

@Slf4j
@Configuration
@EnableConfigurationProperties(OAuth2ClientProperties.class)
@Conditional(ClientsConfiguredCondition.class)
public class FeignClientConfig {

  @Bean
  Logger.Level feignLoggerLevel() {
    return Logger.Level.FULL;
  }

  /** feign 使用webflux配置 */
  //  @Bean
  //  public Decoder feignDecoder() {
  //    return new ResponseEntityDecoder(new SpringDecoder(feignHttpMessageConverter()));
  //  }
  //
  //  public ObjectFactory<HttpMessageConverters> feignHttpMessageConverter() {
  //    final HttpMessageConverters httpMessageConverters =
  //        new HttpMessageConverters(new MappingJackson2HttpMessageConverter());
  //    return () -> httpMessageConverters;
  //  }

  @Bean
  public OAuth2AuthorizedClientManager authorizedClientManager(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
    AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager =
        new AuthorizedClientServiceOAuth2AuthorizedClientManager(
            clientRegistrationRepository, oAuth2AuthorizedClientService);
    authorizedClientManager.setAuthorizedClientProvider(
        new ClientCredentialsOAuth2AuthorizedClientProvider());
    return authorizedClientManager;
  }

  @Bean
  public RequestInterceptor oauth2FeignRequestInterceptor(
      OAuth2AuthorizedClientManager authorizedClientManager) {
    return new OAuth2FeignRequestInterceptor(authorizedClientManager, "user-server");
  }

  @Bean
  public WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
    ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
        new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
    oauth2Client.setDefaultClientRegistrationId("user-server");
    return WebClient.builder().apply(oauth2Client.oauth2Configuration()).build();
  }
}
