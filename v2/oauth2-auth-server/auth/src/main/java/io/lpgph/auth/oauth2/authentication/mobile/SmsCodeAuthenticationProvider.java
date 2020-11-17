package io.lpgph.auth.oauth2.authentication.mobile;

import io.lpgph.auth.oauth2.MobileUserDetailsService;
import io.lpgph.auth.oauth2.RegisterUserService;
import io.lpgph.auth.oauth2.service.ISmsCodeService;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Objects;

/** @see org.springframework.security.authentication.dao.DaoAuthenticationProvider */
@Getter
@Setter
@Slf4j
public class SmsCodeAuthenticationProvider implements AuthenticationProvider {

  private UserDetailsService userDetailsService;
  private RegisterUserService registerUserService;
  // 使用远程服务或者redis中取  建议从 短信服务 中取
  private ISmsCodeService smsCodeService;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    log.info("手机验证码认证 ！！！");
    SmsCodeAuthenticationToken authenticationToken = (SmsCodeAuthenticationToken) authentication;

    String mobile = (String) authenticationToken.getPrincipal();
    String code = (String) authenticationToken.getCredentials();
    // 找到该手机的验证码  将验证码进行比对
    String checkCode = smsCodeService.getCode(mobile);
    if (!Objects.equals(code.toUpperCase(), checkCode.toUpperCase())) {
      throw new InternalAuthenticationServiceException("手机验证码不正确！");
    }
    // 认证成功后通知验证码失效
    smsCodeService.invalid(mobile, "");
    // 根据用户手机号获取用户
    UserDetails user = userDetailsService.loadUserByUsername(mobile);
    // 如果用户不存在 则创建该用户
    if (user == null) {
      registerUserService.register(mobile, null);
      // 邀请注册 则抛出异常 否则直接进行注册
//      throw new UsernameNotFoundException("用户没有注册！");
    }

    // 认证成功  手机验证码认证  不需要设置密码
    SmsCodeAuthenticationToken authenticationResult =
        new SmsCodeAuthenticationToken(user, null, user.getAuthorities());
    authenticationResult.setDetails(authenticationToken.getDetails());
    return authenticationResult;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    // 该SmsCodeAuthenticationProvider智支持SmsCodeAuthenticationToken的token认证
    return SmsCodeAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
