# Spring cloud security oauth2 实现SSO认证， 网关整合客户端

## V1版本使用session
## v2版本使用jwt


## 问题记录
1. 网关整合client 访问认证端报错 原因是在同一网关下，解决方案要么使用两个不同的IP 127.0.0.1和当前IP 或者 添加
```yaml
server:
  servlet:
    session:
      cookie:
        name: s1
```
2. 认证服务器添加userInfo 需要启用@EnableResourceServer,添加一份资源服务配置文件，自定义userInfo接口

## 参考
[Spring Security Docs](https://docs.spring.io/spring-security/site/docs/5.4.1/reference/html5/) <br>
[Spring Cloud Security Docs](https://docs.spring.io/spring-cloud-security/docs/2.2.4.RELEASE/reference/html/) <br>
[OAuth 2.0 Login Sample](https://github.com/spring-projects/spring-security/tree/master/samples/boot/oauth2login) <br>
[Gateway OAuth 2.0 Login Sample](https://github.com/spring-cloud-samples/sample-gateway-oauth2login) <br>
#### SSO登录
    https://github.com/lenve/oauth2-samples.git 
    https://github.com/spring-cloud-samples/sample-gateway-oauth2login.git 
### 实现多种登录方式
    https://gitee.com/lvhaibao/spring-lhbauth.git 
###  Json登录
    https://github.com/dk980241/spring-boot-security-demo.git 
### 授权登录 
    https://www.cnblogs.com/cjsblog/p/9241217.html 
### 微信授权
    https://github.com/sunjc/wechat-api
    https://blog.51cto.com/7308310/2457336
    https://blog.csdn.net/qq_33417321/article/details/108614245
### 前后端分离
    https://segmentfault.com/a/1190000016583573 
    https://juejin.im/post/6844903974546456590
    https://blog.csdn.net/u013642886/article/details/90697541
    https://blog.csdn.net/qq_34997906/article/details/97007709
### 参考
    https://segmentfault.com/u/lenve/articles 
    https://segmentfault.com/u/awbeci/articles 
    https://blog.csdn.net/u011857851/category_9389904.html 
### 其他
    https://www.baeldung.com/sso-spring-security-oauth2 
    https://github.com/Baeldung/spring-security-oauth/tree/master/oauth-sso 

### Resource feign
    https://github.com/liangxiaobo/test-security-oauth2

### 认证服务和授权服务
    整合则是 把授权服务和用户服务放到一起  分离反之
    认证放到用户这里  授权则调用auth
### 整合实例
https://spring.io/guides/tutorials/spring-security-and-angular-js/
https://github.com/spring-guides/tut-spring-security-and-angular-js/tree/master/oauth2