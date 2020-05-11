> 本文由 [简悦 SimpRead](http://ksria.com/simpread/) 转码， 原文地址 https://segmentfault.com/a/1190000021081318

> SpringBoot 实战电商项目 mall（20k+star）地址：[https://github.com/macrozheng/mall](https://github.com/macrozheng/mall)

摘要
--

Spring Cloud Security 为构建安全的 SpringBoot 应用提供了一系列解决方案，结合 Oauth2 还可以实现更多功能，比如使用 JWT 令牌存储信息，刷新令牌功能，本文将对其结合 JWT 使用进行详细介绍。

JWT 简介
------

> JWT 是 JSON WEB TOKEN 的缩写，它是基于 RFC 7519 标准定义的一种可以安全传输的的 JSON 对象，由于使用了数字签名，所以是可信任和安全的。

### JWT 的组成

*   JWT token 的格式：header.payload.signature；
*   header 中用于存放签名的生成算法；

```
{
  "alg": "HS256",
  "typ": "JWT"
}
```

*   payload 中用于存放数据，比如过期时间、用户名、用户所拥有的权限等；

```
{
  "exp": 1572682831,
  "user_name": "macro",
  "authorities": [
    "admin"
  ],
  "jti": "c1a0645a-28b5-4468-b4c7-9623131853af",
  "client_id": "admin",
  "scope": [
    "all"
  ]
}
```

*   signature 为以 header 和 payload 生成的签名，一旦 header 和 payload 被篡改，验证将失败。

### JWT 实例

*   这是一个 JWT 的字符串：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NzI2ODI4MzEsInVzZXJfbmFtZSI6Im1hY3JvIiwiYXV0aG9yaXRpZXMiOlsiYWRtaW4iXSwianRpIjoiYzFhMDY0NWEtMjhiNS00NDY4LWI0YzctOTYyMzEzMTg1M2FmIiwiY2xpZW50X2lkIjoiYWRtaW4iLCJzY29wZSI6WyJhbGwiXX0.x4i6sRN49R6JSjd5hd1Fr2DdEMBsYdC4KB6Uw1huXPg
```

*   可以在该网站上获得解析结果：[https://jwt.io/](https://jwt.io/)

![](https://segmentfault.com/img/remote/1460000021081323)

创建 oauth2-jwt-server 模块
-----------------------

该模块只是对 oauth2-server 模块的扩展，直接复制过来扩展下下即可。

oauth2 中存储令牌的方式
---------------

> 在上一节中我们都是把令牌存储在内存中的，这样如果部署多个服务，就会导致无法使用令牌的问题。  
> Spring Cloud Security 中有两种存储令牌的方式可用于解决该问题，一种是使用 Redis 来存储，另一种是使用 JWT 来存储。

### 使用 Redis 存储令牌

*   在 pom.xml 中添加 Redis 相关依赖：

```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

*   在 application.yml 中添加 redis 相关配置：

```
spring:
  redis: 
    password: 123456
```

*   添加在 Redis 中存储令牌的配置：

```
@Configuration
public class RedisTokenStoreConfig {

    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

    @Bean
    public TokenStore redisTokenStore (){
        return new RedisTokenStore(redisConnectionFactory);
    }
}
```

*   在认证服务器配置中指定令牌的存储策略为 Redis：

```
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @Autowired
    @Qualifier("redisTokenStore")
    private TokenStore tokenStore;

    
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.authenticationManager(authenticationManager)
                .userDetailsService(userService)
                .tokenStore(tokenStore);
    }
    
    
}
```

*   运行项目后使用密码模式来获取令牌，访问如下地址：[http://localhost](http://localhost/):9401/oauth/token

![](https://segmentfault.com/img/remote/1460000021081322)

*   进行获取令牌操作，可以发现令牌已经被存储到 Redis 中。

![](https://segmentfault.com/img/remote/1460000021081324)

### 使用 JWT 存储令牌

*   添加使用 JWT 存储令牌的配置：

```
@Configuration
public class JwtTokenStoreConfig {

    @Bean
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
        accessTokenConverter.setSigningKey("test_key");
        return accessTokenConverter;
    }
}
```

*   在认证服务器配置中指定令牌的存储策略为 JWT：

```
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @Autowired
    @Qualifier("jwtTokenStore")
    private TokenStore tokenStore;
    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;
    @Autowired
    private JwtTokenEnhancer jwtTokenEnhancer;

    
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.authenticationManager(authenticationManager)
                .userDetailsService(userService)
                .tokenStore(tokenStore) 
                .accessTokenConverter(jwtAccessTokenConverter);
    }
    
    
}
```

*   运行项目后使用密码模式来获取令牌，访问如下地址：[http://localhost](http://localhost/):9401/oauth/token

![](https://segmentfault.com/img/remote/1460000021081326)

*   发现获取到的令牌已经变成了 JWT 令牌，将 access_token 拿到 [https://jwt.io/](https://jwt.io/) 网站上去解析下可以获得其中内容。

```
{
  "exp": 1572682831,
  "user_name": "macro",
  "authorities": [
    "admin"
  ],
  "jti": "c1a0645a-28b5-4468-b4c7-9623131853af",
  "client_id": "admin",
  "scope": [
    "all"
  ]
}
```

扩展 JWT 中存储的内容
-------------

> 有时候我们需要扩展 JWT 中存储的内容，这里我们在 JWT 中扩展一个 key 为`enhance`，value 为`enhance info`的数据。

*   继承 TokenEnhancer 实现一个 JWT 内容增强器：

```
public class JwtTokenEnhancer implements TokenEnhancer {
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        Map<String, Object> info = new HashMap<>();
        info.put("enhance", "enhance info");
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(info);
        return accessToken;
    }
}
```

*   创建一个 JwtTokenEnhancer 实例：

```
@Configuration
public class JwtTokenStoreConfig {
    
    

    @Bean
    public JwtTokenEnhancer jwtTokenEnhancer() {
        return new JwtTokenEnhancer();
    }
}
```

*   在认证服务器配置中配置 JWT 的内容增强器：

```
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @Autowired
    @Qualifier("jwtTokenStore")
    private TokenStore tokenStore;
    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;
    @Autowired
    private JwtTokenEnhancer jwtTokenEnhancer;

    
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
        List<TokenEnhancer> delegates = new ArrayList<>();
        delegates.add(jwtTokenEnhancer); 
        delegates.add(jwtAccessTokenConverter);
        enhancerChain.setTokenEnhancers(delegates);
        endpoints.authenticationManager(authenticationManager)
                .userDetailsService(userService)
                .tokenStore(tokenStore) 
                .accessTokenConverter(jwtAccessTokenConverter)
                .tokenEnhancer(enhancerChain);
    }

    
}
```

*   运行项目后使用密码模式来获取令牌，之后对令牌进行解析，发现已经包含扩展的内容。

```
{
  "user_name": "macro",
  "scope": [
    "all"
  ],
  "exp": 1572683821,
  "authorities": [
    "admin"
  ],
  "jti": "1ed1b0d8-f4ea-45a7-8375-211001a51a9e",
  "client_id": "admin",
  "enhance": "enhance info"
}
```

Java 中解析 JWT 中的内容
-----------------

> 如果我们需要获取 JWT 中的信息，可以使用一个叫 jjwt 的工具包。

*   在 pom.xml 中添加相关依赖：

```
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.0</version>
</dependency>
```

*   修改 UserController 类，使用 jjwt 工具类来解析 Authorization 头中存储的 JWT 内容。

```
@RestController
@RequestMapping("/user")
public class UserController {
    @GetMapping("/getCurrentUser")
    public Object getCurrentUser(Authentication authentication, HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        String token = StrUtil.subAfter(header, "bearer ", false);
        return Jwts.parser()
                .setSigningKey("test_key".getBytes(StandardCharsets.UTF_8))
                .parseClaimsJws(token)
                .getBody();
    }

}
```

*   将令牌放入`Authorization`头中，访问如下地址获取信息：[http://localhost](http://localhost/):9401/user/getCurrentUser

![](https://segmentfault.com/img/remote/1460000021081327)

刷新令牌
----

> 在 Spring Cloud Security 中使用 oauth2 时，如果令牌失效了，可以使用刷新令牌通过 refresh_token 的授权模式再次获取 access_token。

*   只需修改认证服务器的配置，添加 refresh_token 的授权模式即可。

```
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("admin")
                .secret(passwordEncoder.encode("admin123456"))
                .accessTokenValiditySeconds(3600)
                .refreshTokenValiditySeconds(864000)
                .redirectUris("http://www.baidu.com")
                .autoApprove(true) 
                .scopes("all")
                .authorizedGrantTypes("authorization_code","password","refresh_token"); 
    }
}
```

*   使用刷新令牌模式来获取新的令牌，访问如下地址：[http://localhost](http://localhost/):9401/oauth/token

![](https://segmentfault.com/img/remote/1460000021081325)

使用到的模块
------

```
springcloud-learning
└── oauth2-jwt-server
```

项目源码地址
------

[https://github.com/macrozheng/springcloud-learning](https://github.com/macrozheng/springcloud-learning)

公众号
---

[mall 项目](https://github.com/macrozheng/mall)全套学习教程连载中，**关注公众号**第一时间获取。

![](https://segmentfault.com/img/remote/1460000021057703)