package io.lpgph.auth.config;

import io.lpgph.auth.oauth2.filter.JwtAuthenticationTokenFilter;
import io.lpgph.auth.oauth2.handler.DefaultAuthenticationEntryPoint;
import io.lpgph.auth.oauth2.handler.DefaultAuthenticationFailureHandler;
import io.lpgph.auth.oauth2.handler.DefaultLogoutSuccessHandler;
import io.lpgph.auth.oauth2.handler.JwtAuthenticationSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired private UserDetailsService customUserDetailsService;

  //  @Autowired private DefaultAuthenticationSuccessHandler authenticationSuccessHandler;

  @Autowired private JwtAuthenticationSuccessHandler authenticationSuccessHandler;

  @Autowired private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;

  //  @Autowired private JsonAuthenticationSecurityConfig jsonAuthenticationSecurityConfig;
  //
  //  @Autowired private SmsCodeAuthenticationSecurityConfig smsCodeAuthenticationSecurityConfig;

  @Autowired private PasswordEncoder passwordEncoder;

  @Override
  public void configure(WebSecurity web) throws Exception {
    web.ignoring().antMatchers("/login.html", "/css/**", "/js/**", "/images/**");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
        .antMatchers("/oauth/**", "/login/**")
        .permitAll()
        .anyRequest()
        .authenticated()
        .and()
        .formLogin() // 授权服务端的登录 客户端登录直接调用action
        .loginProcessingUrl("/login")
        .successHandler(authenticationSuccessHandler)
        .failureHandler(new DefaultAuthenticationFailureHandler())
        .and()
        .logout()
        .logoutSuccessHandler(new DefaultLogoutSuccessHandler())
        .and()
        .exceptionHandling()
        .authenticationEntryPoint(new DefaultAuthenticationEntryPoint())
        //        .and()
        //        .cors()// 允许跨域
        .and()
        .csrf()
        .disable() // 不使用session  CRSF禁用，
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session设置为无状态  不通过session管理
        .and()
        //        .sessionManagement()
        //        .disable() // 禁用session
        .anonymous()
        .disable()
        // 解决不允许显示在iframe的问题
        .headers()
        .frameOptions()
        .disable()
        .cacheControl();

    // 添加JWT解析  授权登录不使用session而使用token处理
    http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
    //    http.addFilterBefore(
    //        (Filter) jwtAuthenticationTokenFilter,
    //        (Class<? extends Filter>) UsernamePasswordAuthenticationFilter.class);

    //
    // http.apply(jsonAuthenticationSecurityConfig).and().apply(smsCodeAuthenticationSecurityConfig);
  }

  //    @Autowired
  //    private SecurityProperties securityProperties;

  //    /**
  //     * cors跨域
  //     *
  //     * @return
  //     */
  //    @Bean
  //    public CorsConfigurationSource corsConfigurationSource() {
  //        CorsConfiguration corsConfiguration = new CorsConfiguration();
  //        corsConfiguration.addAllowedOrigin("*");
  //        corsConfiguration.addAllowedHeader("*");
  //        corsConfiguration.addAllowedMethod("*");
  //        corsConfiguration.setAllowCredentials(true);
  //        corsConfiguration.setMaxAge(3600L);
  //        corsConfiguration.addExposedHeader("access-control-allow-methods");
  //        corsConfiguration.addExposedHeader("access-control-allow-headers");
  //        corsConfiguration.addExposedHeader("access-control-allow-origin");
  //        corsConfiguration.addExposedHeader("access-control-max-age");
  //        corsConfiguration.addExposedHeader("X-Frame-Options");
  //
  //        UrlBasedCorsConfigurationSource configurationSource = new
  // UrlBasedCorsConfigurationSource();
  //        configurationSource.registerCorsConfiguration("/**", corsConfiguration);
  //        return configurationSource;
  //    }

  /** 用户验证 */
  @Override
  public void configure(AuthenticationManagerBuilder authenticationManagerBuilder)
      throws Exception {
    authenticationManagerBuilder
        .userDetailsService(this.customUserDetailsService)
        .passwordEncoder(passwordEncoder); // 账号密码登录时重新刷新密码
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }
}
