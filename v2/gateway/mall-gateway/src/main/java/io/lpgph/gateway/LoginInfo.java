package io.lpgph.gateway;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class LoginInfo {
    private String username;
    private String password;
    private String appId;
}
