package io.lpgph.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.bootstrap.encrypt.KeyProperties;

@SpringBootApplication
@EnableConfigurationProperties({KeyProperties.class})
public class AuthApplication {
    public static void main(String args[]) {
        SpringApplication.run(AuthApplication.class, args);
    }
}

