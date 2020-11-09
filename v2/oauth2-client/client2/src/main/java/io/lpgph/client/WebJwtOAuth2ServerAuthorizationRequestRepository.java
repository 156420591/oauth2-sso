package io.lpgph.client;

import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * @see org.springframework.security.oauth2.client.web.server.WebSessionOAuth2ServerAuthorizationRequestRepository
 */
public class WebJwtOAuth2ServerAuthorizationRequestRepository implements ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    @Override
    public Mono<OAuth2AuthorizationRequest> loadAuthorizationRequest(ServerWebExchange exchange) {
        return null;
    }

    @Override
    public Mono<Void> saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, ServerWebExchange exchange) {
        return null;
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> removeAuthorizationRequest(ServerWebExchange exchange) {
        return null;
    }
}
