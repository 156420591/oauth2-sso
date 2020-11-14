package io.lpgph.client;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.server.session.DefaultWebSessionManager;
import org.springframework.web.server.session.HeaderWebSessionIdResolver;
import org.springframework.web.server.session.WebSessionIdResolver;
import org.springframework.web.server.session.WebSessionManager;

//import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
//import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

@Configuration
//@EnableRedisHttpSession
public class HttpSessionConfig {


    // override the default of using cookies and instead use headers
//    @Bean
//    public LettuceConnectionFactory connectionFactory() {
//        return new LettuceConnectionFactory();
//    }

//    @Bean
//    public ReactorSessionRepository sessionRepository() {
//        return new MapReactorSessionRepository(new ConcurrentHashMap<>());
//    }

    @Bean
    public WebSessionIdResolver webSessionIdResolver() {
        HeaderWebSessionIdResolver resolver = new HeaderWebSessionIdResolver();
        resolver.setHeaderName("X-SESSION-ID");
        return resolver;
    }

    @Bean
    public WebSessionManager sessionManager(){
        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        sessionManager.setSessionIdResolver(webSessionIdResolver());
        return sessionManager;
    }
}
