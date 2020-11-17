package io.lpgph.auth.oauth2;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface RegisterUserService {
  UserDetails register(String principal, String credentials);
}
