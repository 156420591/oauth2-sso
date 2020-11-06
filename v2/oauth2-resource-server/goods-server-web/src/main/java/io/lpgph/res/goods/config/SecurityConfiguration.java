package io.lpgph.res.goods.config;

import io.lpgph.res.goods.security.WebSecurity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.security.interfaces.RSAPublicKey;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * OAuth2ResourceServerSecurityConfiguration
 */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Value("${spring.security.oauth2.resourceserver.jwt.public-key-location}")
    private RSAPublicKey key;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests(
                (authorizeRequests) ->
                        authorizeRequests
                                .antMatchers("/user/username", "/user/show")
                                .permitAll()
                                //                    .antMatchers(HttpMethod.POST)
                                //                    .access("#oauth2.hasScope('wirte')")
                                //                    .antMatchers(HttpMethod.GET)
                                //                    .access("#oauth2.hasScope('read')")
//                    .antMatchers("/**")
//                    .access("@permission.check(authentication,request)")
                                .anyRequest()
                                .authenticated())
                .oauth2ResourceServer(
                        oauth2ResourceServer -> oauth2ResourceServer.jwt(jwt -> jwt.decoder(jwtDecoder())))
//                .oauth2Client(spec -> jwtDecoder());
                .oauth2Client(withDefaults());
    }

    @Bean
    WebSecurity permission() {
        return new WebSecurity();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(this.key).build();
    }
}
