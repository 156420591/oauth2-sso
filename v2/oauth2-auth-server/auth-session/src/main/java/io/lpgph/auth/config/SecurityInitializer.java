package io.lpgph.auth.config;

import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

public class SecurityInitializer extends AbstractSecurityWebApplicationInitializer {

  public SecurityInitializer() {
    super(WebSecurityConfig.class, HttpSessionConfig.class);
  }
}
