package io.lpgph.auth.oauth2.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * @see org.springframework.security.web.context.HttpSessionSecurityContextRepository
 * @see org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
 */
@Slf4j
public class TokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public TokenAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(new AntPathRequestMatcher("/login", "POST")); // 参考 UsernamePasswordAuthenticationFilter
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        String token = request.getHeader("auth-token");
        String username = "";
        String password = "";
        List<? extends GrantedAuthority> authorities = new ArrayList<>();

        return new UsernamePasswordAuthenticationToken(username,password, authorities);
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        Authentication auth = null;

        // 默认创建 session
//        allowSessionCreation.set(true);

        // 如果 header 里有 auth-token 时，则使用 token 查询用户数据进行登陆验证
        if (request.getHeader("auth-token") != null) {
            // 1. 尝试进行身份认证
            // 2. 如果用户无效，则返回 401
            // 3. 如果用户有效，则保存到 SecurityContext 中，供本次方式后续使用
            auth = attemptAuthentication(request, response);

            if (auth == null) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token 无效，请重新申请 token");
                return;
            }

            // 保存认证信息到 SecurityContext，禁止 HttpSessionSecurityContextRepository 创建 session
//            allowSessionCreation.set(false);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        // 继续调用下一个 filter: UsernamePasswordAuthenticationToken
        chain.doFilter(request, response);
//        super.doFilter(req, res, chain);
    }


}
