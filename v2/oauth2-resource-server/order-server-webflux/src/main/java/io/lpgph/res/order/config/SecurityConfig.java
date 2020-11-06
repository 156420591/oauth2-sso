package io.lpgph.res.order.config;

import io.lpgph.res.order.security.MergeAuthoritiesConverter;
import io.lpgph.res.order.security.PathMatchReactiveAuthorizationManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPublicKey;

import static org.springframework.security.config.Customizer.withDefaults;

@Slf4j
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Value("${spring.security.oauth2.resourceserver.jwt.public-key-location}")
    private RSAPublicKey key;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 注意 根据路径匹配 如果路径没有认证改通过 则会直接返回认证失败
     */
    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        log.info("\n\n  初始化  \n\n");
        /*
         * 根据 scope 划分客户端权限的  如资源客户端之间远程调用
         * 其他的权限根据角色的权限划分
         * 应该没有我考虑的那么麻烦  之前考虑是先验证客户端权限 然后验证角色权限  似乎过了
         *
         */
        http.authorizeExchange(
                exchanges ->
                        exchanges
                                .pathMatchers("/web/**")  // 无需登录即可访问
                                .permitAll()
                                .pathMatchers("/rpc/**")   // 提供给客户端之间的远程调用接口
                                .hasAuthority("SCOPE_RPC")
                                .pathMatchers("/user/info") // 提供给授权认证客户端查询用户信息接口
                                .authenticated()

                                /*
                                 * 一个系统对应多个APP
                                 * A 商城系统  B 商家系统  那么A B 都可以访问用户信息  A 可以访问用户订单接口 商城商品接口 不能访问商家接口
                                 * B 只能访问商家的订单接口  商家的商品接口
                                 * 单点登录呢？
                                 * 在访问
                                 */
                                .pathMatchers("/user/**")  // 提供普通用户接口  通过指定客户端的用户可以访问
                                .hasAuthority("SCOPE_USER")

                                // 商家是需要认证的 所以这里是角色
                                .pathMatchers("/merchant/p/**") // 提供给商家接口公共接口
                                .hasAuthority("ROLE_MERCHANT")
                                .pathMatchers("/merchant/a/**")  // 开发者接口 需要权限认证
                                .access(PathMatchReactiveAuthorizationManager.authenticated())

                                // 开发者是需要认证的 所以这里是角色
                                .pathMatchers("/dev/p/**") // 开发者接口 公共接口
                                .hasAuthority("ROLE_DEV")
                                .pathMatchers("/dev/a/**")  // 开发者接口 需要权限认证
                                .access(PathMatchReactiveAuthorizationManager.authenticated())

                                .pathMatchers("/admin/**")   // 提供管理员的接口  需要对请求进行权限验证
                                .access(PathMatchReactiveAuthorizationManager.authenticated())
                                .anyExchange()  // 其他剩下的接口 都需要认证 这里考虑是简单认证 还是复杂认证
                                .authenticated())
                .oauth2ResourceServer(
                        oauth2ResourceServer ->
                                oauth2ResourceServer.jwt(
                                        jwt ->
                                                jwt.jwtDecoder(jwtDecoder())
                                                        .jwtAuthenticationConverter(getJwtAuthenticationConverter())))
//                .oauth2Client(spec -> jwtDecoder());
                .oauth2Client(withDefaults());
        return http.build();
    }

    /**
     * see
     * https://docs.spring.io/spring-security/site/docs/5.4.1/reference/html5/#webflux-oauth2resourceserver-jwt-authorization
     * 手动提取权限属性
     */
    public Converter<Jwt, Mono<AbstractAuthenticationToken>> getJwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter =
                new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("authorities");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        return new ReactiveJwtAuthenticationConverterAdapter(converter);
    }

    /**
     * see
     * https://docs.spring.io/spring-security/site/docs/5.4.1/reference/html5/#oauth2resourceserver-jwt-claimsetmapping
     * 可以解决不同服务器之间时间差, Claim转换 移除 添加 重命名 合并等
     */
    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        //    NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(this.key).build()
        NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withPublicKey(this.key).build();
        // 如果服务器之间时间不一致 可以设置时间差来解决
        //    OAuth2TokenValidator<Jwt> withClockSkew = new DelegatingOAuth2TokenValidator<>(
        //            new JwtTimestampValidator(Duration.ofSeconds(60)));
        //    jwtDecoder.setJwtValidator(withClockSkew);
        // 将 客户端 scope 和 用户 authorities 合并到 authorities
        /*
         * 认证服务器中可以设置 client 的 authorities 但是如果用户存在 authorities 时会覆盖 client 的 authorities
         *  根据 oauth2 手册 只有scope属性 这个属性格式是根据自己的需求定义的 可以写成角色 也可以写成请求路径
         * see https://oauth.net/2/
         */
        jwtDecoder.setClaimSetConverter(new MergeAuthoritiesConverter());
        return jwtDecoder;
    }
}
