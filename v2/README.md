

认证 authentication
授权 authorization

该系统中认证授权是放在一起的  如果拆分 

uaa-gateway  单独的网关
authentication 认证 指的是当前用户的身份，解决 “我是谁？”的问题，当用户登陆过后系统便能追踪到他的身份并做出符合相应业务逻辑的操作 
    认证服务包含 用户的信息以及认证方式 如账号密码登录 微信授权  手机验证码 
authorization 授权 指的是什么样的身份被允许访问某些资源，解决“我能做什么？”的问题，在获取到用户身份后继续检查用户的权限
    根据用户认证成功后生成的凭证(credentials) 如sessionId,token等进行授权 生成token
    
    
http://seanthefish.com/2020/07/24/micro-service-authorization/index.html
https://insights.thoughtworks.cn/api-2/
https://www.oauth.com/
https://www.cnblogs.com/linianhui/p/openid-connect-core.html
https://www.ruanyifeng.com/blog/2014/05/oauth_2_0.html
https://www.jianshu.com/p/50ade6f2e4fd

https://github.com/Snailclimb/spring-security-jwt-guide/blob/master/docs/SpringSecurity%E4%BB%8B%E7%BB%8D.md
http://qtdebug.com/spring-security-8-token/

认证返回sessionId 或token
    过滤器中需要通过cookie或header中token获取authentication 并存储到上下文中
然后根据认证服务获取授权token