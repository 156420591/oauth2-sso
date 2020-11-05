package io.lpgph.auth.oauth2.enhancer;

import io.lpgph.auth.common.json.JsonUtil;
import com.google.common.collect.Maps;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.Map;

/** 自定义token携带内容 */
@Slf4j
public class CustomTokenEnhancer implements TokenEnhancer {

  @Override
  public OAuth2AccessToken enhance(
      OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

    log.info("\n\n\n\n 添加token附加信息 \n{}\n\n\n", JsonUtil.toJson(authentication));

    if (authentication.getUserAuthentication()!=null ){

    }

    //        // 添加额外信息的map
    //        final Map<String, Object> additionMessage = new HashMap<>(2);
    //        // 获取当前登录的用户
    //        AdminUserDetail admin = (AdminUserDetail)
    // oAuth2Authentication.getUserAuthentication().getPrincipal();
    //
    //        // 如果用户不为空 则把id放入jwt token中
    //        additionMessage.put(AuthConst.ADMIN, JsonUtil.toJson(new
    // AdminInfo(admin.getBaseUser().getId(), admin.getBaseUser().getUid())));
    ////            additionMessage.put("permissions",JsonUtil.toJson(admin.getPermissions()));
    //        ((DefaultOAuth2AccessToken)
    // oAuth2AccessToken).setAdditionalInformation(additionMessage);
//            log.info("当前用户为：                   {}", oAuth2AccessToken.getValue());

//    UserInfo userInfo = (UserInfo) authentication.getUserAuthentication().getPrincipal();

//    log.info("authentication.getUserAuthentication()：                   {}", authentication.getUserAuthentication());
    Map<String, Object> additionalInfo = Maps.newHashMap();
    // 自定义token内容，加入组织机构信息
//    additionalInfo.put("userId", userInfo.getId());
    ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
    return accessToken;
  }
}
