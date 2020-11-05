package io.lpgph.res.order.security;

import io.lpgph.res.order.json.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.util.AntPathMatcher;
import reactor.core.publisher.Mono;

import java.util.Arrays;

/**
 * see
 * https://docs.spring.io/spring-security/site/docs/5.3.1.BUILD-SNAPSHOT/reference/html5/#authz-authorities
 */
@Slf4j
public class WebFluxReactiveAuthorizationManager
        implements ReactiveAuthorizationManager<AuthorizationContext> {

    private static final AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Override
    public Mono<AuthorizationDecision> check(
            Mono<Authentication> authentication, AuthorizationContext object) {


        //    String uri = object.getExchange().getRequest().getURI().getPath();
        //    String method = object.getExchange().getRequest().getMethodValue();
        //    String authority = uri + ":" + method;
        log.info("\n\n\n权限验证 Authentication\n{}\n\n\n", JsonUtil.toJson(authentication));
        //    return authentication
        //        .filter(Authentication::isAuthenticated)
        //        .flatMapIterable(
        //            a -> ((JwtAuthenticationToken) a).getToken().getClaimAsStringList("authorities"))
        //        .any(a -> antPathMatcher.match(a, authority))
        //        .map(AuthorizationDecision::new)
        //        .defaultIfEmpty(new AuthorizationDecision(false));

        String uri = object.getExchange().getRequest().getURI().getPath();
        String method = object.getExchange().getRequest().getMethodValue();

        return authentication
                .filter(Authentication::isAuthenticated)
                .flatMapIterable(
                        a -> {
                            log.info("\n\n\n权限验证\n{}\n\n\n", JsonUtil.toJson(a));
                            JwtAuthenticationToken token =  ((JwtAuthenticationToken) a);
//                token.getToken().getClaims()
                            return ((JwtAuthenticationToken) a).getToken().getClaimAsStringList("authorities");
                            // return (Collection<RESTfulGrantedAuthority>) a.getAuthorities();
                        })
                .any(
                        a -> {
                            String[] auth = a.split(":");
                            log.info("\n\n\n{}\n{}\n\n", JsonUtil.toJson(a), Arrays.toString(auth));
                            return antPathMatcher.match(auth[0], uri)
                                    && (method.equals(auth[1]) || "ALL".equals(auth[1]));
                        })
                //        .any(
                //            a -> {
                //              log.info(JsonUtil.toJson(a));
                //              return antPathMatcher.match(a.getUrl(), uri)
                //                  && (method.equals(a.getMethod()) || "ALL".equals(a.getMethod()));
                //            })
                .map(AuthorizationDecision::new)
                .defaultIfEmpty(new AuthorizationDecision(false));
    }

    /** */
    public static WebFluxReactiveAuthorizationManager authenticated() {
        return new WebFluxReactiveAuthorizationManager();
    }

    private WebFluxReactiveAuthorizationManager() {}
}
