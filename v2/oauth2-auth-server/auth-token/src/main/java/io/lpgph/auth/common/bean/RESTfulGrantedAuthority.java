package io.lpgph.auth.common.bean;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

@Data
public class RESTfulGrantedAuthority implements GrantedAuthority {

    private String url;
    private String method;

    public RESTfulGrantedAuthority(String url, String method) {
        this.url = url;
        this.method = method;
    }

    @Override
    public String getAuthority() {
        return this.url + ":" + this.method;
    }
}