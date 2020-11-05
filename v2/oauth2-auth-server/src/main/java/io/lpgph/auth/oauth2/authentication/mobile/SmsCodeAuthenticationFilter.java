package io.lpgph.auth.oauth2.authentication.mobile;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** 自定义 UsernamePasswordAuthenticationFilter 支持表单或json请求 */
@Slf4j
public class SmsCodeAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

  public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "mobile";
  public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "code";

  private String mobileParameter = SPRING_SECURITY_FORM_USERNAME_KEY;
  private String codeParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;
  private boolean postOnly = true;

  public SmsCodeAuthenticationFilter() {
    super(new AntPathRequestMatcher("/login/mobile", "POST"));
  }

  @Override
  public Authentication attemptAuthentication(
      HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
    if (postOnly && !request.getMethod().equalsIgnoreCase(HttpMethod.POST.toString())) {
      // 不支持的请求方式
      throw new AuthenticationServiceException("不支持的请求方式: " + request.getMethod());
    }

    String mobile = obtainMobile(request);
    String code = obtainCode(request);
    if (mobile == null) {
      mobile = "";
    }
    if (code == null) {
      code = "";
    }
    mobile = mobile.trim();

    SmsCodeAuthenticationToken authenticationToken = new SmsCodeAuthenticationToken(mobile, code);
    setDetails(request, authenticationToken);
    return this.getAuthenticationManager().authenticate(authenticationToken);
  }

  @Nullable
  protected String obtainCode(HttpServletRequest request) {
    return request.getParameter(codeParameter);
  }

  @Nullable
  protected String obtainMobile(HttpServletRequest request) {
    return request.getParameter(mobileParameter);
  }

  protected void setDetails(HttpServletRequest request, SmsCodeAuthenticationToken authRequest) {
    authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
  }

  public void setMobileParameter(String mobileParameter) {
    Assert.hasText(mobileParameter, "Mobile parameter must not be empty or null");
    this.mobileParameter = mobileParameter;
  }

  public void setCodeParameter(String codeParameter) {
    Assert.hasText(codeParameter, "Code parameter must not be empty or null");
    this.codeParameter = codeParameter;
  }

  public void setPostOnly(boolean postOnly) {
    this.postOnly = postOnly;
  }

  public final String getMobileParameter() {
    return mobileParameter;
  }

  public final String getCodeParameter() {
    return codeParameter;
  }
}
