package io.lpgph.res.order.security;

import io.lpgph.res.order.json.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.Assert;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * see
 * https://docs.spring.io/spring-security/site/docs/5.3.1.BUILD-SNAPSHOT/reference/html5/#authz-authorities
 * 自定义过滤链 如果通过 authorities 没有匹配到 则通过url匹配 SCOPE 是客户端权限范围 请求链是用户权限 请求链在SCOPE内
 *
 * @see org.springframework.security.authorization.AuthorityReactiveAuthorizationManager
 */
@Slf4j
public class AuthorityReactiveAuthorizationManager
    implements ReactiveAuthorizationManager<AuthorizationContext> {

  private static final String DEFAULT_SCOPE_PREFIX = "SCOPE_";

  private static final String DEFAULT_AUTHORITY_PREFIX = "AUTH_";

  private final String scopePrefix = DEFAULT_SCOPE_PREFIX;

  private final String authPrefix = DEFAULT_AUTHORITY_PREFIX;

  private final List<String> scopes;

  private AuthorityReactiveAuthorizationManager() {
    this.scopes = Collections.emptyList();
  }

  private AuthorityReactiveAuthorizationManager(String... scopes) {
    this.scopes = Arrays.asList(scopes);
  }

  private static final AntPathMatcher antPathMatcher = new AntPathMatcher();

  @Override
  public Mono<AuthorizationDecision> check(
      Mono<Authentication> authentication, AuthorizationContext object) {
    // 获取当前请求的路径
    String uri = object.getExchange().getRequest().getURI().getPath();
    String method = object.getExchange().getRequest().getMethodValue();

    // 先是客户端认证  客户端认证通过 判断是否有权限
    // 先判断 客户端认证范围是否存在
    Mono<Map<Boolean, String>> authorityMap =
        authentication
            .filter(Authentication::isAuthenticated)
            .flatMapIterable(Authentication::getAuthorities)
            .map(GrantedAuthority::getAuthority)
            .collectMap(a -> a.startsWith(authPrefix));

    if (scopes.isEmpty()) {
      return authorityMap
          .filter(a -> a.containsKey(true))
          .flatMapIterable(Map::values)
          .any(a -> match(a.substring(0, authPrefix.length() - 1), uri, method))
          .map(AuthorizationDecision::new)
          .defaultIfEmpty(new AuthorizationDecision(false));
    }
    if (authorityMap.subscribe(a -> a.get(true)).isDisposed()) {
      return authentication
          .filter(Authentication::isAuthenticated)
          .flatMapIterable(Authentication::getAuthorities)
          .map(GrantedAuthority::getAuthority)
          .any(this.scopes::contains)
          .map(AuthorizationDecision::new)
          .defaultIfEmpty(new AuthorizationDecision(false));
    }
    return authentication
        .filter(Authentication::isAuthenticated)
        .flatMapIterable(Authentication::getAuthorities)
        .map(GrantedAuthority::getAuthority)
        .any(this.scopes::contains)
        .map(AuthorizationDecision::new)
        .defaultIfEmpty(new AuthorizationDecision(false));
  }

  private boolean match(String a, String uri, String method) {
    if (a.split(":").length != 2) return false;
    String[] auth = a.split(":");
    return antPathMatcher.match(auth[0], uri) && (method.equals(auth[1]) || "ALL".equals(auth[1]));
  }

  public static AuthorityReactiveAuthorizationManager authenticated() {
    return new AuthorityReactiveAuthorizationManager();
  }

  public static AuthorityReactiveAuthorizationManager hasScope(String scope) {
    Assert.notNull(scope, "scope cannot be null");
    return new AuthorityReactiveAuthorizationManager(scope);
  }

  public static AuthorityReactiveAuthorizationManager hasAnyScope(String... scopes) {
    Assert.notNull(scopes, "scopes cannot be null");
    for (String scope : scopes) {
      Assert.notNull(scope, "scope cannot be null");
    }
    return new AuthorityReactiveAuthorizationManager(scopes);
  }
}
