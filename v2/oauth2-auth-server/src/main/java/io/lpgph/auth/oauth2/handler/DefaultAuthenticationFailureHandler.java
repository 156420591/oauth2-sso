package io.lpgph.auth.oauth2.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class DefaultAuthenticationFailureHandler implements AuthenticationFailureHandler {
  @Override
  public void onAuthenticationFailure(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
      throws IOException, ServletException {
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    PrintWriter out = response.getWriter();
    HttpStatus status = HttpStatus.UNAUTHORIZED;
    String msg = null;
    if (exception instanceof LockedException) {
      msg = "账户被锁定，请联系管理员!";
    } else if (exception instanceof CredentialsExpiredException) {
      msg = "密码过期，请联系管理员!";
    } else if (exception instanceof AccountExpiredException) {
      msg = "账户过期，请联系管理员!";
    } else if (exception instanceof DisabledException) {
      msg = "账户被禁用，请联系管理员!";
    } else if (exception instanceof BadCredentialsException) {
      msg = "用户名或者密码输入错误，请重新输入!";
    }
    response.sendError(status.value(), msg);
  }
}
