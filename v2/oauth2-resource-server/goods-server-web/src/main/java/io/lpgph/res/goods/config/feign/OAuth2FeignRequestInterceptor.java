/*
 * Copyright 2015-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.lpgph.res.goods.config.feign;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

@Slf4j
public class OAuth2FeignRequestInterceptor implements RequestInterceptor {

  /** The name of the token. */
  public static final String BEARER = "Bearer";

  /** The name of the header. */
  public static final String AUTHORIZATION = "Authorization";

  private final String tokenType;

  private final String header;

  private final OAuth2AuthorizedClientManager authorizedClientManager;

  private final String registrationId;

  public OAuth2FeignRequestInterceptor(
      OAuth2AuthorizedClientManager authorizedClientManager, String registrationId) {
    this(authorizedClientManager, registrationId, BEARER, AUTHORIZATION);
  }

  public OAuth2FeignRequestInterceptor(
      OAuth2AuthorizedClientManager authorizedClientManager,
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
    String token = extract(tokenType);
    log.info("\n\nclient token\n{}\n\n", token);
    template.header(header, token);
  }

  protected String extract(String tokenType) {
    OAuth2AccessToken accessToken = getToken();
    return String.format("%s %s", tokenType, accessToken.getTokenValue());
  }

  public OAuth2AccessToken getToken() {
    log.info("\n\nregistrationId {}\n\n", registrationId);
    OAuth2AuthorizeRequest request =
        OAuth2AuthorizeRequest.withClientRegistrationId(registrationId)
            .principal(registrationId)
            .build();
    OAuth2AuthorizedClient auth2AuthorizedClient = authorizedClientManager.authorize(request);
    if (auth2AuthorizedClient == null) {
      throw new ClientAuthorizationRequiredException(registrationId);
    }
    return auth2AuthorizedClient.getAccessToken();
  }
}
