package io.lpgph.auth.oauth2.handler;

import io.lpgph.auth.common.json.JsonUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class DefaultAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {
    Object principal = authentication.getPrincipal();
    log.info("\n\n\n 登录成功 {}\n\n\n", JsonUtil.toJson(authentication));
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    PrintWriter out = response.getWriter();
    out.write(new ObjectMapper().writeValueAsString(principal));
    out.flush();
    out.close();
  }
}
