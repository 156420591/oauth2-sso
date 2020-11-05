package io.lpgph.auth.oauth2.service;

/** 短信服务 */
public interface ISmsCodeService {

  void sendCode(String phone);

  String getCode(String phone);

  void invalid(String phone,String code);
}
