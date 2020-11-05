package io.lpgph.client;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class UiSecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  public void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests().anyRequest().authenticated().and().csrf().disable();
    //        http.antMatcher("/**")
    //                .authorizeRequests()
    //                .antMatchers("/")
    //                .permitAll()
    //                .anyRequest()
    //                .authenticated()
    //                .and()
    //                .oauth2Login();
  }
}
