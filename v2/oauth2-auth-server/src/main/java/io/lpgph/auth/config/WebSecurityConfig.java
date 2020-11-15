package io.lpgph.auth.config;

import io.lpgph.auth.oauth2.filter.JwtAuthenticationTokenFilter;
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

import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/** 登录只负责客户端授权登录 */
@Slf4j
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired private UserDetailsService customUserDetailsService;

  @Autowired private PasswordEncoder passwordEncoder;

  @Autowired private CorsConfigurationSource corsConfigurationSource;

  /*
   * org.springframework.security.web.context.SecurityContextRepository;
   * org.springframework.security.web.context.HttpSessionSecurityContextRepository
   * 默认使用session来进行管理
   */

  @Override
  public void configure(WebSecurity web) throws Exception {
    web.ignoring().antMatchers("/login.html", "/css/**", "/js/**", "/images/**", "/**.ico");
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
        //                .loginPage("/login.html")
        .loginProcessingUrl("/login")
        //                .successHandler(authenticationSuccessHandler)  //  登录成功后返回jwt
        //                .failureHandler(new DefaultAuthenticationFailureHandler())
        .permitAll()
        .and()
        .logout()
        //                .logoutSuccessHandler(new DefaultLogoutSuccessHandler())
        //                .and()
        //                .exceptionHandling()
        //                .authenticationEntryPoint(new DefaultAuthenticationEntryPoint()) //
        // 自定义未登录结果 系统默认未登录会跳转到登录页
        .permitAll()
        .and()
        .cors() // 跨域 配置
        .configurationSource(corsConfigurationSource)
        //        .and()
        //        .sessionManagement()
        //        .sessionCreationPolicy(SessionCreationPolicy.NEVER)
        .and()
        .csrf()
        .disable()
        .anonymous()
        .disable()
        // 解决不允许显示在iframe的问题
        .headers()
        .frameOptions()
        .disable()
        .cacheControl();
    http.addFilter(new JwtAuthenticationTokenFilter(authenticationManager()));
  }

  //    @Autowired
  //    private SecurityProperties securityProperties;

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
