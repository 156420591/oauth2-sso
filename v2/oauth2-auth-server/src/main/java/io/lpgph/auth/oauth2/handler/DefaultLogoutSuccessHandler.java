package io.lpgph.auth.oauth2.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class DefaultLogoutSuccessHandler implements LogoutSuccessHandler {

  @Override
  public void onLogoutSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {
    // session配置为无状态，或者不保存session，这里authentication为null！
    /*
     * Jwt 登出
     * 1. 如果和redis结合 可以在次删除存储在redis中的token
     * 2. 可以修改客户端凭证？？？
     */
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    log.info("注销成功 [{}]", null == authentication ? null : authentication.getName());
    response.setStatus(HttpStatus.OK.value());
  }
}
