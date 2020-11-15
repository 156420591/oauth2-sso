package io.lpgph.auth.oauth2.service.impl;

import io.lpgph.auth.oauth2.service.ISmsCodeService;
import org.springframework.stereotype.Service;

/** 将短信验证码 保存到redis中 通过短信服务发送 */
@Service
public class SmsCodeServiceImpl implements ISmsCodeService {
  @Override
  public void sendCode(String phone) {

    // redis存储  设置失效时间
    // 短信服务发送

  }

  @Override
  public String getCode(String phone) {
    return "123456";
  }

  @Override
  public void invalid(String phone, String code) {
    // 验证码使用后立即失效
  }
}
