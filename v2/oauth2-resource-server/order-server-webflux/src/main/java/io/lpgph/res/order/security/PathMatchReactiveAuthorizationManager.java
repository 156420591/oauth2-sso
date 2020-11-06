package io.lpgph.res.order.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.util.AntPathMatcher;
import reactor.core.publisher.Mono;

/**
 * see
 * https://docs.spring.io/spring-security/site/docs/5.3.1.BUILD-SNAPSHOT/reference/html5/#authz-authorities
 * 自定义过滤链 如果通过 authorities 没有匹配到 则通过url匹配
 * SCOPE 是客户端权限范围 请求链是用户权限  请求链在SCOPE内
 *
 * @see org.springframework.security.authorization.AuthorityReactiveAuthorizationManager
 */
@Slf4j
public class PathMatchReactiveAuthorizationManager
        implements ReactiveAuthorizationManager<AuthorizationContext> {

    private PathMatchReactiveAuthorizationManager() {
    }

    private static final AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Override
    public Mono<AuthorizationDecision> check(
            Mono<Authentication> authentication, AuthorizationContext object) {
        // 获取当前请求的路径
        String uri = object.getExchange().getRequest().getURI().getPath();
        String method = object.getExchange().getRequest().getMethodValue();
        return authentication
                .filter(Authentication::isAuthenticated)
                .flatMapIterable(Authentication::getAuthorities)
                .map(GrantedAuthority::getAuthority)
                .any(a -> match(a, uri, method))
                .map(AuthorizationDecision::new)
                .defaultIfEmpty(new AuthorizationDecision(false));
    }

    private boolean match(String a, String uri, String method) {
        if (a.split(":").length != 2) return false;
        String[] auth = a.split(":");
        return antPathMatcher.match(auth[0], uri) && (method.equals(auth[1]) || "ALL".equals(auth[1]));
    }

    public static PathMatchReactiveAuthorizationManager authenticated() {
        return new PathMatchReactiveAuthorizationManager();
    }

}
