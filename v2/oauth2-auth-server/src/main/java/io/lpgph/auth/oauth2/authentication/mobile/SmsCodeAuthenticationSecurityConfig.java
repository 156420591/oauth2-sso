package io.lpgph.auth.oauth2.authentication.mobile;

import io.lpgph.auth.oauth2.MobileUserDetailsService;
import io.lpgph.auth.oauth2.RegisterUserService;
import io.lpgph.auth.oauth2.service.ISmsCodeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.Filter;

@Component
public class SmsCodeAuthenticationSecurityConfig
    extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

  @Autowired private MobileUserDetailsService userDetailsService;

  @Autowired private AuthenticationSuccessHandler loginAuthenticationSuccessHandler;

  @Autowired private ISmsCodeService smsCodeService;

  @Override
  public void configure(HttpSecurity http) throws Exception {
    SmsCodeAuthenticationFilter smsCodeFilter = new SmsCodeAuthenticationFilter();
    // 设置AuthenticationManager
    smsCodeFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
    //    smsCodeFilter.setUsernameParameter("phone");
    //    smsCodeFilter.setPasswordParameter("code");
    //    smsCodeFilter.setFilterProcessesUrl("/login/phone");
    // 设置成功失败处理器
    smsCodeFilter.setAuthenticationSuccessHandler(loginAuthenticationSuccessHandler);
    // 设置 provider
    SmsCodeAuthenticationProvider smsCodeAuthenticationProvider =
        new SmsCodeAuthenticationProvider();
    smsCodeAuthenticationProvider.setUserDetailsService(userDetailsService);
    smsCodeAuthenticationProvider.setRegisterUserService(userDetailsService);
    smsCodeAuthenticationProvider.setSmsCodeService(smsCodeService);

    http.authenticationProvider(smsCodeAuthenticationProvider)
        .addFilterAfter(smsCodeFilter, UsernamePasswordAuthenticationFilter.class);
  }
}
