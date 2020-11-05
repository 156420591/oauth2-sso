package io.lpgph.res.order.security;

import io.lpgph.res.order.json.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.util.StringUtils;

import java.util.*;

/** 将client 中的 scope 和 用户或client authorities 合并 */
@Slf4j
public class MergeAuthoritiesConverter
    implements Converter<Map<String, Object>, Map<String, Object>> {

  private static final String DEFAULT_SCOPE_PREFIX = "SCOPE_";

  private static final String DEFAULT_AUTHORITY_PREFIX = "AUTH_";

  private static final String DEFAULT_CLAIMS_SCOPE_NAME = "scope";

  private static final String DEFAULT_CLAIMS_AUTHORITIES_NAME = "authorities";

  private String scopePrefix = DEFAULT_SCOPE_PREFIX;

  private String authPrefix = DEFAULT_AUTHORITY_PREFIX;

  private String scopeName = DEFAULT_CLAIMS_SCOPE_NAME;

  private String authoritiesName = DEFAULT_CLAIMS_AUTHORITIES_NAME;

  private final MappedJwtClaimSetConverter delegate =
      MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());

  @Override
  public Map<String, Object> convert(Map<String, Object> claims) {
    Map<String, Object> convertedClaims = this.delegate.convert(claims);
    log.info("JWT信息 {}", JsonUtil.toJson(convertedClaims));
    List<String> authoritiesList = new ArrayList<>();
    // 客户端权限范围 scope 和 用户权限范围 authorities
    for (String scope : getCollection(convertedClaims, scopeName)) {
      authoritiesList.add(this.scopePrefix + scope);
    }
    for (String authority : getCollection(convertedClaims, authoritiesName)) {
      authoritiesList.add(this.authPrefix + authority);
    }
    convertedClaims.put(authoritiesName, authoritiesList);
    log.info("JWT合并 {}", JsonUtil.toJson(convertedClaims));
    return convertedClaims;
  }

  private Collection<String> getCollection(Map<String, Object> convertedClaims, String key) {
    String claimName = convertedClaims.containsKey(key) ? key : null;
    if (claimName == null) {
      return Collections.emptyList();
    }
    Object authorities = convertedClaims.get(claimName);
    if (authorities instanceof String) {
      if (StringUtils.hasText((String) authorities)) {
        return Arrays.asList(((String) authorities).split(" "));
      } else {
        return Collections.emptyList();
      }
    } else if (authorities instanceof Collection) {
      //noinspection unchecked
      return (Collection<String>) authorities;
    }
    return Collections.emptyList();
  }

  public void setScopePrefix(String scopePrefix) {
    this.scopePrefix = scopePrefix;
  }

  public void setAuthPrefix(String authPrefix) {
    this.authPrefix = authPrefix;
  }

  public void setScopeName(String scopeName) {
    this.scopeName = scopeName;
  }

  public void setAuthoritiesName(String authoritiesName) {
    this.authoritiesName = authoritiesName;
  }
}
