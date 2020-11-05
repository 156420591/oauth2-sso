package io.lpgph.res.order.config.feign;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

@Slf4j
public class OAuth2FeignRequestInterceptor implements RequestInterceptor {

  /** The name of the token. */
  public static final String BEARER = "Bearer";

  /** The name of the header. */
  public static final String AUTHORIZATION = "Authorization";

  private final String tokenType;

  private final String header;

  private final ReactiveOAuth2AuthorizedClientManager authorizedClientManager;

  private final String registrationId;

  public OAuth2FeignRequestInterceptor(
      ReactiveOAuth2AuthorizedClientManager authorizedClientManager, String registrationId) {
    this(authorizedClientManager, registrationId, BEARER, AUTHORIZATION);
  }

  public OAuth2FeignRequestInterceptor(
      ReactiveOAuth2AuthorizedClientManager authorizedClientManager,
      String registrationId,
      String tokenType,
      String header) {
    this.tokenType = tokenType;
    this.header = header;
    this.authorizedClientManager = authorizedClientManager;
    this.registrationId = registrationId;
  }

  @Override
  public void apply(RequestTemplate template) {
    template.header(header);
    template.header(header, extract(tokenType));
  }

  protected String extract(String tokenType) {
    OAuth2AccessToken accessToken = getToken();
    return String.format("%s %s", tokenType, accessToken.getTokenValue());
  }

  public OAuth2AccessToken getToken() {
    OAuth2AuthorizeRequest request =
        OAuth2AuthorizeRequest.withClientRegistrationId(registrationId)
            .principal(registrationId)
            .build();
    OAuth2AuthorizedClient auth2AuthorizedClient =
        authorizedClientManager.authorize(request).block();
    if (auth2AuthorizedClient == null) {
      throw new ClientAuthorizationRequiredException(registrationId);
    }
    return auth2AuthorizedClient.getAccessToken();
  }
}
