package io.lpgph.auth.oauth2.authentication.json;

import io.lpgph.auth.common.json.TypeReference;
import io.lpgph.auth.common.json.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

/**
 * 支持json请求
 *
 * @see org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
 */
@Slf4j
public class JsonUsernamePasswordAuthenticationFilter
    extends AbstractAuthenticationProcessingFilter {

  public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";
  public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";

  private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;
  private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;
  private boolean postOnly = true;

  public JsonUsernamePasswordAuthenticationFilter() {
    super(new AntPathRequestMatcher("/login/json", "POST"));
  }

  @Override
  public Authentication attemptAuthentication(
      HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
    if (postOnly && !request.getMethod().equalsIgnoreCase(HttpMethod.POST.toString())) {
      // 不支持的请求方式
      throw new AuthenticationServiceException("不支持的请求方式: " + request.getMethod());
    }
    if (!MediaType.APPLICATION_JSON_VALUE.equalsIgnoreCase(request.getContentType())) {
      throw new AuthenticationServiceException("不支持的请求内容格式: " + request.getContentType());
    }

    String username = null;
    String password = null;

    String str = getJson(request);
    Map<String, String> map = JsonUtil.fromJson(str, new TypeReference<>() {});
    if (map != null) {
      username = map.get(usernameParameter);
      password = map.get(passwordParameter);
    }

    if (username == null) {
      username = "";
    }

    if (password == null) {
      password = "";
    }
    username = username.trim();

    UsernamePasswordAuthenticationToken authenticationToken =
        new UsernamePasswordAuthenticationToken(username, password);
    setDetails(request, authenticationToken);
    return this.getAuthenticationManager().authenticate(authenticationToken);
  }

  private String getJson(HttpServletRequest request) {
    // 解析request内容
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setExpandEntityReferences(false);
    StringBuilder sb = new StringBuilder();
    try (InputStream inputStream = request.getInputStream();
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream))) {
      String str;
      while ((str = bufferedReader.readLine()) != null) {
        sb.append(str);
      }
    } catch (IOException ex) {
      throw new RuntimeException("获取请求内容异常", ex);
    }
    return sb.toString();
  }

  protected void setDetails(
      HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
    authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
  }

  public void setUsernameParameter(String usernameParameter) {
    Assert.hasText(usernameParameter, "Username parameter must not be empty or null");
    this.usernameParameter = usernameParameter;
  }

  public void setPasswordParameter(String passwordParameter) {
    Assert.hasText(passwordParameter, "Password parameter must not be empty or null");
    this.passwordParameter = passwordParameter;
  }

  public void setPostOnly(boolean postOnly) {
    this.postOnly = postOnly;
  }

  public final String getUsernameParameter() {
    return usernameParameter;
  }

  public final String getPasswordParameter() {
    return passwordParameter;
  }
}
