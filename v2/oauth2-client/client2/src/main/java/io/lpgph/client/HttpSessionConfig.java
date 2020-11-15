package io.lpgph.client;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.server.session.HeaderWebSessionIdResolver;
import org.springframework.web.server.session.WebSessionIdResolver;

@Configuration
public class HttpSessionConfig {

  @Bean
  public WebSessionIdResolver webSessionIdResolver() {
    HeaderWebSessionIdResolver resolver = new HeaderWebSessionIdResolver();
    resolver.setHeaderName("X-SESSION-ID");
    return resolver;
  }
}
