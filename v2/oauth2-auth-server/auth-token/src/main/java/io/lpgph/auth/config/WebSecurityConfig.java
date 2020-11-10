package io.lpgph.auth.config;

import io.lpgph.auth.oauth2.filter.JwtAuthenticationTokenFilter;
import io.lpgph.auth.oauth2.handler.DefaultAuthenticationEntryPoint;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/** 登录后生成JWT JwtAuthenticationSuccessHandler 授权登录使用JWT获取授权信息 JwtAuthenticationTokenFilter */
@Slf4j
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired private UserDetailsService customUserDetailsService;

  @Autowired private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;

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
        .formLogin() // 禁用登录 登录使用自定义登录
        .disable()
        .logout()
        .and()
        .exceptionHandling()
        .authenticationEntryPoint(new DefaultAuthenticationEntryPoint()) //  自定义未登录结果 系统默认未登录会跳转到登录页
        .and()
        .cors() // 跨域 配置
        .configurationSource(corsConfigurationSource())
        .and()
        .csrf()
        .disable() // 不使用session  CRSF禁用，
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session设置为无状态  不通过session管理
        .and()
        .anonymous()
        .disable()
        // 解决不允许显示在iframe的问题
        .headers()
        .frameOptions()
        .disable()
        .cacheControl();

    // 添加JWT解析  授权登录不使用session而使用token处理
    http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
    // 使用json登录而不是表单登录
    // http.apply(jsonAuthenticationSecurityConfig).and().apply(smsCodeAuthenticationSecurityConfig);
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration corsConfiguration = new CorsConfiguration();
    corsConfiguration.addAllowedOrigin("*");
    corsConfiguration.addAllowedHeader("*");
    corsConfiguration.addAllowedMethod("*");
    corsConfiguration.setAllowCredentials(true);
    corsConfiguration.setMaxAge(3600L);
    corsConfiguration.addExposedHeader("access-control-allow-methods");
    corsConfiguration.addExposedHeader("access-control-allow-headers");
    corsConfiguration.addExposedHeader("access-control-allow-origin");
    corsConfiguration.addExposedHeader("access-control-max-age");
    corsConfiguration.addExposedHeader("X-Frame-Options");
    UrlBasedCorsConfigurationSource configurationSource = new UrlBasedCorsConfigurationSource();
    configurationSource.registerCorsConfiguration("/**", corsConfiguration);
    return configurationSource;
  }

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
