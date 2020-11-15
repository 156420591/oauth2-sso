package io.lpgph.auth.common.bean;

import lombok.Getter;
import lombok.ToString;

@ToString
@Getter
public class LoginInfo {
  private String username;
  private String password;
}
