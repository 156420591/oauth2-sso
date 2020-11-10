package io.lpgph.auth;

import io.lpgph.auth.common.bean.LoginInfo;
import io.lpgph.auth.common.json.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;
import java.util.Map;

@SpringBootTest
//@Transactional
@Slf4j
public class SpringTest {

    @Test
    public void psd() {
        BCryptPasswordEncoder bcryptPasswordEncoder = new BCryptPasswordEncoder();
        log.info(bcryptPasswordEncoder.encode("admin"));
        log.info(bcryptPasswordEncoder.encode("test"));

//        admin $2a$10$Q24s6DpxXUepuDHWCBJfZ.S4e9EaKVb1GOdnjIj4aIeOlLG67.s4e
//        test $2a$10$UkK3MX3cFytw2DTnM1mDcO1o60xkP0vegHb8EccVkpimzqIbFfcFa
    }

    @Test
    void utilTest() {
        String str = "{username:\"admin\",password:\"admin\"}";

        LoginInfo info2 = JsonUtil.fromJson(str);
        log.info("\n\n\n{}\n\n\n", info2.toString());

        LoginInfo info = JsonUtil.fromJson(str, LoginInfo.class);
        log.info("\n\n\n{}\n\n\n", info.toString());
        Map<String,String> map = JsonUtil.fromJson(str);
        log.info("\n\n\n{}\n\n\n", map.toString());

    }

    @Test
    void utilTest2() {
        String str = "[{username:\"admin\",password:\"admin\"}]";
        List<LoginInfo> infoList = JsonUtil.fromJson(str);
        log.info("\n\n\n{}\n\n\n", infoList.toString());
        List<Map<String,String>> listMap = JsonUtil.fromJson(str);
        log.info("\n\n\n{}\n\n\n", infoList.toString());
    }

}
