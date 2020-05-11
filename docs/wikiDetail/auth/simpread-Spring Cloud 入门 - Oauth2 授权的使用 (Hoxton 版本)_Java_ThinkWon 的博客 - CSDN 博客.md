> 本文由 [简悦 SimpRead](http://ksria.com/simpread/) 转码， 原文地址 https://blog.csdn.net/ThinkWon/article/details/103761687

### 文章目录

*   [Spring Cloud 入门系列汇总](#Spring_Cloud_4)
*   [摘要](#_30)
*   [OAuth2 简介](#OAuth2__36)
*   [OAuth2 相关名词解释](#OAuth2__42)
*   [四种授权模式](#_51)
*   [两种常用的授权模式](#_60)

*   [授权码模式](#_62)
*   [密码模式](#_74)

*   [Oauth2 的使用](#Oauth2_84)

*   [创建 oauth2-server 模块](#oauth2server_86)
*   [授权码模式使用](#_273)
*   [密码模式使用](#_315)

*   [使用到的模块](#_331)
*   [项目源码地址](#_340)

> 项目使用的 Spring Cloud 为 Hoxton 版本，Spring Boot 为 2.2.2.RELEASE 版本

Spring Cloud 入门系列汇总
-------------------

| 序号 | 内容 | 链接地址 |
| --- | --- | --- |
| 1 | Spring Cloud 入门 - 十分钟了解 Spring Cloud | [https://blog.csdn.net/ThinkWon/article/details/103715146](https://blog.csdn.net/ThinkWon/article/details/103715146) |
| 2 | Spring Cloud 入门 - Eureka 服务注册与发现 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103726655](https://blog.csdn.net/ThinkWon/article/details/103726655) |
| 3 | Spring Cloud 入门 - Ribbon 服务消费者 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103729080](https://blog.csdn.net/ThinkWon/article/details/103729080) |
| 4 | Spring Cloud 入门 - Hystrix 断路器 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103732497](https://blog.csdn.net/ThinkWon/article/details/103732497) |
| 5 | Spring Cloud 入门 - Hystrix Dashboard 与 Turbine 断路器监控 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103734664](https://blog.csdn.net/ThinkWon/article/details/103734664) |
| 6 | Spring Cloud 入门 - OpenFeign 服务消费者 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103735751](https://blog.csdn.net/ThinkWon/article/details/103735751) |
| 7 | Spring Cloud 入门 - Zuul 服务网关 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103738851](https://blog.csdn.net/ThinkWon/article/details/103738851) |
| 8 | Spring Cloud 入门 - Config 分布式配置中心 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103739628](https://blog.csdn.net/ThinkWon/article/details/103739628) |
| 9 | Spring Cloud 入门 - Bus 消息总线 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103753372](https://blog.csdn.net/ThinkWon/article/details/103753372) |
| 10 | Spring Cloud 入门 - Sleuth 服务链路跟踪 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103753896](https://blog.csdn.net/ThinkWon/article/details/103753896) |
| 11 | Spring Cloud 入门 - Consul 服务注册发现与配置中心 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103756139](https://blog.csdn.net/ThinkWon/article/details/103756139) |
| 12 | Spring Cloud 入门 - Gateway 服务网关 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103757927](https://blog.csdn.net/ThinkWon/article/details/103757927) |
| 13 | Spring Cloud 入门 - Admin 服务监控中心 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103758697](https://blog.csdn.net/ThinkWon/article/details/103758697) |
| 14 | Spring Cloud 入门 - Oauth2 授权的使用 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103761687](https://blog.csdn.net/ThinkWon/article/details/103761687) |
| 15 | Spring Cloud 入门 - Oauth2 授权之 JWT 集成 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103763364](https://blog.csdn.net/ThinkWon/article/details/103763364) |
| 16 | Spring Cloud 入门 - Oauth2 授权之基于 JWT 完成单点登录 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103766368](https://blog.csdn.net/ThinkWon/article/details/103766368) |
| 17 | Spring Cloud 入门 - Nacos 实现注册和配置中心 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103769680](https://blog.csdn.net/ThinkWon/article/details/103769680) |
| 18 | Spring Cloud 入门 - Sentinel 实现服务限流、熔断与降级 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103770879](https://blog.csdn.net/ThinkWon/article/details/103770879) |
| 19 | Spring Cloud 入门 - Seata 处理分布式事务问题 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103786102](https://blog.csdn.net/ThinkWon/article/details/103786102) |
| 20 | Spring Cloud 入门 - 汇总篇 (Hoxton 版本) | [https://blog.csdn.net/ThinkWon/article/details/103786588](https://blog.csdn.net/ThinkWon/article/details/103786588) |

摘要
--

Spring Cloud Security 为构建安全的 SpringBoot 应用提供了一系列解决方案，结合 Oauth2 可以实现单点登录、令牌中继、令牌交换等功能，本文将对其结合 Oauth2 入门使用进行详细介绍。

OAuth2 简介
---------

OAuth 2.0 是用于授权的行业标准协议。OAuth 2.0 为简化客户端开发提供了特定的授权流，包括 Web 应用、桌面应用、移动端应用等。

OAuth2 相关名词解释
-------------

*   Resource owner（资源拥有者）：拥有该资源的最终用户，他有访问资源的账号密码；
*   Resource server（资源服务器）：拥有受保护资源的服务器，如果请求包含正确的访问令牌，可以访问资源；
*   Client（客户端）：访问资源的客户端，会使用访问令牌去获取资源服务器的资源，可以是浏览器、移动设备或者服务器；
*   Authorization server（授权服务器）：用于授权用户的服务器，如果客户端授权通过，发放访问资源服务器的令牌。

四种授权模式
------

*   Authorization Code（授权码模式）：正宗的 OAuth2 的授权模式，客户端先将用户导向授权服务器，登录后获取授权码，然后进行授权，最后根据授权码获取访问令牌；
*   Implicit（简化模式）：和授权码模式相比，取消了获取授权码的过程，直接获取访问令牌；
*   Resource Owner Password Credentials（密码模式）：客户端直接向用户获取用户名和密码，之后向授权服务器获取访问令牌；
*   Client Credentials（客户端模式）：客户端直接通过客户端授权（比如 client_id 和 client_secret）从授权服务器获取访问令牌。

两种常用的授权模式
---------

### 授权码模式

![](https://img-blog.csdnimg.cn/20191230100103543.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly90aGlua3dvbi5ibG9nLmNzZG4ubmV0,size_16,color_FFFFFF,t_70)

*   (A) 客户端将用户导向授权服务器；
*   (B) 用户在授权服务器进行登录并授权；
*   © 授权服务器返回授权码给客户端；
*   (D) 客户端通过授权码和跳转地址向授权服务器获取访问令牌；
*   (E) 授权服务器发放访问令牌（有需要带上刷新令牌）。

### 密码模式

![](https://img-blog.csdnimg.cn/20191230100125217.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly90aGlua3dvbi5ibG9nLmNzZG4ubmV0,size_16,color_FFFFFF,t_70)

*   (A) 客户端从用户获取用户名和密码；
*   (B) 客户端通过用户的用户名和密码访问授权服务器；
*   © 授权服务器返回访问令牌（有需要带上刷新令牌）。

Oauth2 的使用
----------

### 创建 oauth2-server 模块

> 这里我们创建一个 oauth2-server 模块作为授权服务器来使用。

在 pom.xml 中添加相关依赖：

```
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.cloud</groupId>
	<artifactId>spring-cloud-starter-oauth2</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.cloud</groupId>
	<artifactId>spring-cloud-starter-security</artifactId>
</dependency>
```

在 application.yml 中进行配置：

```
server:
  port: 9401

spring:
  application:
    name: oauth2-server
```

添加 UserService 实现 UserDetailsService 接口，用于加载用户信息：

```
@Service
public class UserService implements UserDetailsService {

    private List<User> userList;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostConstruct
    public void initData() {
        String password = passwordEncoder.encode("123456");
        userList = new ArrayList<>();

        userList.add(new User("jourwon",password, AuthorityUtils.commaSeparatedStringToAuthorityList("admin")));
        userList.add(new User("andy",password, AuthorityUtils.commaSeparatedStringToAuthorityList("client")));
        userList.add(new User("mark",password, AuthorityUtils.commaSeparatedStringToAuthorityList("client")));
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<User> findUserList = userList.stream().filter(user -> user.getUsername().equals(username)).collect(Collectors.toList());
        if (!CollectionUtils.isEmpty(findUserList)) {
            return findUserList.get(0);
        } else {
            throw new UsernameNotFoundException("用户名或密码错误");
        }
    }

}
```

添加授权服务器配置，使用 @EnableAuthorizationServer 注解开启：

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

    /**
     * 使用密码模式需要配置
     *
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
                .userDetailsService(userService);
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                // 配置client_id
                .withClient("admin")
                // 配置client_secret
                .secret(passwordEncoder.encode("admin123456"))
                // 配置访问token的有效期
                .accessTokenValiditySeconds(3600)
                // 配置刷新token的有效期
                .refreshTokenValiditySeconds(864000)
                // 配置redirect_uri,用于授权成功后的跳转
                .redirectUris("http://www.baidu.com")
                // 配置申请的权限范围
                .scopes("all")
                // 配置grant_type,表示授权类型
                .authorizedGrantTypes("authorization_code", "password");
    }
}
```

添加资源服务器配置，使用 @EnableResourceServer 注解开启：

```
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .requestMatchers()
                // 配置需要保护的资源路径
                .antMatchers("/user/**");
    }

}
```

添加 SpringSecurity 配置，允许授权相关路径的访问及表单登录：

```
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf()
                .disable()
                .authorizeRequests()
                .antMatchers("/oauth/**", "/login/**", "logout/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .permitAll();
    }
}
```

添加需要登录的接口用于测试：

```
@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping("/getCurrentUser")
    public Object getCurrentUser(Authentication authentication) {
        return authentication.getPrincipal();
    }

}
```

### 授权码模式使用

启动 oauth2-server 服务；

在浏览器访问该地址进行登录授权：[http://localhost:9401/oauth/authorize?response_type=code&client_id=admin&redirect_uri=http://www.baidu.com&scope=all&state=normal](http://localhost:9401/oauth/authorize?response_type=code&client_id=admin&redirect_uri=http://www.baidu.com&scope=all&state=normal)

输入账号密码进行登录操作：

![](https://img-blog.csdnimg.cn/20191230100158609.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly90aGlua3dvbi5ibG9nLmNzZG4ubmV0,size_16,color_FFFFFF,t_70)

登录后进行授权操作：

![](https://img-blog.csdnimg.cn/20191230100403481.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly90aGlua3dvbi5ibG9nLmNzZG4ubmV0,size_16,color_FFFFFF,t_70)

之后会浏览器会带着授权码跳转到我们指定的路径：

```
https://www.baidu.com/?code=cbM53v&state=normal
```

使用授权码请求该地址获取访问令牌：[http://localhost:9401/oauth/token](http://localhost:9401/oauth/token)

使用 Basic 授权通过 client_id 和 client_secret 构造一个 Authorization 头信息；

![](https://img-blog.csdnimg.cn/20191230100425220.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly90aGlua3dvbi5ibG9nLmNzZG4ubmV0,size_16,color_FFFFFF,t_70)

在 body 中添加以下参数信息，通过 POST 请求获取访问令牌；

![](https://img-blog.csdnimg.cn/20191230100457546.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly90aGlua3dvbi5ibG9nLmNzZG4ubmV0,size_16,color_FFFFFF,t_70)

在请求头中添加访问令牌，访问需要登录授权的接口进行测试，发现已经可以成功访问：[http://localhost:9401/user/getCurrentUser](http://localhost:9401/user/getCurrentUser)

![](https://img-blog.csdnimg.cn/20191230100519493.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly90aGlua3dvbi5ibG9nLmNzZG4ubmV0,size_16,color_FFFFFF,t_70)

### 密码模式使用

使用密码请求该地址获取访问令牌：[http://localhost:9401/oauth/token](http://localhost:9401/oauth/token)

使用 Basic 授权通过 client_id 和 client_secret 构造一个 Authorization 头信息；

![](https://img-blog.csdnimg.cn/20191230100425220.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly90aGlua3dvbi5ibG9nLmNzZG4ubmV0,size_16,color_FFFFFF,t_70)

在 body 中添加以下参数信息，通过 POST 请求获取访问令牌；

![](https://img-blog.csdnimg.cn/20191230100554185.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly90aGlua3dvbi5ibG9nLmNzZG4ubmV0,size_16,color_FFFFFF,t_70)

使用到的模块
------

```
springcloud-learning
└── oauth2-server -- oauth2授权测试服务
```

项目源码地址
------

[GitHub 项目源码地址](https://github.com/JourWon/springcloud-learning)