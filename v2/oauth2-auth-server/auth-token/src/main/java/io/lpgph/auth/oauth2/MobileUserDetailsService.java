package io.lpgph.auth.oauth2;

import io.lpgph.auth.common.bean.RESTfulGrantedAuthority;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@AllArgsConstructor
public class MobileUserDetailsService implements UserDetailsService, RegisterUserService {

  private final PasswordEncoder passwordEncoder;

  @Override
  public UserDetails loadUserByUsername(String mobile) {
    log.info("\n\nUsernameUserDetailService   username {} \n\n", mobile);
    return User.builder()
        .username("admin")
        .password(passwordEncoder.encode("")) // 手机验证码登录 密码为空 不能为null
        .authorities(List.of(new RESTfulGrantedAuthority("/**", "ALL")))
        .build();
  }

  @Override
  public UserDetails register(String principal, String credentials) {
    return null;
  }
}
