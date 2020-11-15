package io.lpgph.auth.config;

import io.lpgph.auth.oauth2.CustomClientDetailsService;
import io.lpgph.auth.oauth2.CustomUserDetailsService;
import io.lpgph.auth.oauth2.MobileUserDetailsService;
import io.lpgph.auth.oauth2.RegisterUserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetailsService;

@Configuration
public class SecurityConfig {

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
    //    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  @Bean
  public ClientDetailsService customClientDetailsService(PasswordEncoder passwordEncoder){
    return new CustomClientDetailsService(passwordEncoder);
  }
  @Bean
  public UserDetailsService customUserDetailsService(PasswordEncoder passwordEncoder){
    return new CustomUserDetailsService(passwordEncoder);
  }
  @Bean
  public UserDetailsService mobileUserDetailsService(PasswordEncoder passwordEncoder){
    return new MobileUserDetailsService(passwordEncoder);
  }

  @Bean
  public RegisterUserService mobileRegisterService(PasswordEncoder passwordEncoder) {
    return new MobileUserDetailsService(passwordEncoder);
  }



}
