package io.lpgph.auth.oauth2;

import io.lpgph.auth.common.bean.RESTfulGrantedAuthority;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@AllArgsConstructor
public class CustomUserDetailsService implements UserDetailsService, RegisterUserService {

  private final PasswordEncoder passwordEncoder;

  @Override
  public UserDetails loadUserByUsername(String username) {
    log.info("\n\nUsernameUserDetailService   username {} \n\n", username);
    return User.builder()
        .username("admin")
        .password(passwordEncoder.encode("admin"))
        .authorities(
            List.of(new RESTfulGrantedAuthority("/**", "ALL"), new SimpleGrantedAuthority("ADMIN")))
        .build();
  }

  @Override
  public UserDetails register(String principal, String credentials) {
    return null;
  }
}
