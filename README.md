
# 《基于Spring Security Oauth2的SSO单点登录+JWT权限控制实践》

## 理论知识

在此之前需要学习和了解一些前置知识包括：

- [**Spring Security**](https://spring.io/projects/spring-security)：基于 `Spring`实现的 `Web`系统的认证和权限模块
- [**OAuth2**](http://www.ruanyifeng.com/blog/2014/05/oauth_2_0.html)：一个关于授权（`authorization`）的开放网络标准
- **单点登录 (SSO)**：在多个应用系统中，用户只需要登录一次就可以访问所有相互信任的应用系统
- [**JWT**](https://jwt.io/)：在网络应用间传递信息的一种基于 `JSON`的开放标准（(`RFC 7519`)，用于作为`JSON`对象在不同系统之间进行安全地信息传输。主要使用场景一般是用来在 身份提供者和服务提供者间传递被认证的用户身份信息

---

## 要完成的目标

- 目标1：设计并实现一个第三方授权中心服务（`Server`），用于完成用户登录，认证和权限处理
- 目标2：可以在授权中心下挂载任意多个客户端应用（`Client`）
- 目标3：当用户访问客户端应用的安全页面时，会重定向到授权中心进行身份验证，认证完成后方可访问客户端应用的服务，且多个客户端应用只需要登录一次即可（谓之 “单点登录 `SSO`”）

基于此目标驱动，本文设计三个独立服务，分别是：
- 一个授权服务中心（`codesheep-server`）
- 客户端应用1（`codesheep-client1`）
- 客户端应用2（`codesheep-client2`）

---

## 多模块（Multi-Module）项目搭建

三个应用通过一个多模块的 `Maven`项目进行组织，其中项目父 `pom`中需要加入相关依赖如下：

```
<dependencies>

	<dependency>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-dependencies</artifactId>
		<version>2.0.8.RELEASE</version>
		<type>pom</type>
		<scope>import</scope>
	</dependency>

	<dependency>
		<groupId>io.spring.platform</groupId>
		<artifactId>platform-bom</artifactId>
		<version>Cairo-RELEASE</version>
		<type>pom</type>
		<scope>import</scope>
	</dependency>

	<dependency>
		<groupId>org.springframework.cloud</groupId>
		<artifactId>spring-cloud-dependencies</artifactId>
		<version>Finchley.SR2</version>
		<type>pom</type>
		<scope>import</scope>
	</dependency>

</dependencies>
```

项目结构如下：



---

## 授权认证中心搭建

授权认证中心本质就是一个 `Spring Boot`应用，因此需要完成几个大步骤：

- **`pom`中添加依赖**

```
<dependencies>
	<dependency>
		<groupId>org.springframework.cloud</groupId>
		<artifactId>spring-cloud-starter-oauth2</artifactId>
	</dependency>
</dependencies>
```

- **项目 `yml`配置文件：**

```
server:
  port: 8085
  servlet:
    context-path: /uac
```

即让授权中心服务启动在本地的 `8085`端口之上

- **创建一个带指定权限的模拟用户**

```
@Component
public class SheepUserDetailsService implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {

        if( !"codesheep".equals(s) )
            throw new UsernameNotFoundException("用户" + s + "不存在" );

        return new User( s, passwordEncoder.encode("123456"), AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_NORMAL,ROLE_MEDIUM"));
    }
}
```

这里创建了一个用户名为`codesheep`，密码 `123456`的模拟用户，并且赋予了 **普通权限**（`ROLE_NORMAL`）和 **中等权限**（`ROLE_MEDIUM`）


- **认证服务器配置 `AuthorizationServerConfig`**

```java
/**
 * 授权服务器
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        // 定义了两个客户端应用的通行证
        clients.inMemory()
                .withClient("sheep1")
                .secret(new BCryptPasswordEncoder().encode("123456"))
                //设置支持[密码模式、授权码模式、token刷新]
                .authorizedGrantTypes("password","authorization_code", "refresh_token")
                .scopes("all")
                .autoApprove(false)
                .and()
                .withClient("sheep2")
                .secret(new BCryptPasswordEncoder().encode("123456"))
                .authorizedGrantTypes("authorization_code", "refresh_token")
                .scopes("all")
                .autoApprove(false);
    }


    /**
     * 注入AuthenticationManager ，密码模式用到
     */
    @Autowired
    private AuthenticationManager authenticationManager;


    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

        // 将增强的token设置到增强链中
        TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
        enhancerChain.setTokenEnhancers(Arrays.asList(customTokenEnhancer(),jwtAccessTokenConverter()));

        // 一个处理链，先添加，再转换
        endpoints.tokenStore(jwtTokenStore()).tokenEnhancer(enhancerChain).accessTokenConverter(jwtAccessTokenConverter());
        DefaultTokenServices tokenServices = (DefaultTokenServices) endpoints.getDefaultAuthorizationServerTokenServices();
        tokenServices.setTokenStore(endpoints.getTokenStore());
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setClientDetailsService(endpoints.getClientDetailsService());
        tokenServices.setTokenEnhancer(endpoints.getTokenEnhancer());
        tokenServices.setAccessTokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(1)); // 一天有效期
        endpoints.tokenServices(tokenServices);
        endpoints.authenticationManager(authenticationManager); //密码模式需要添加
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("isAuthenticated()");
    }

    /**
     * 设置token 由Jwt产生，不使用默认的透明令牌
     */
    @Bean
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    /**
     * 对Jwt签名时，增加一个密钥
     * JwtAccessTokenConverter：对Jwt来进行编码以及解码的类
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter(){
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey("testKey");
        return converter;
    }

    @Bean
    public TokenEnhancer customTokenEnhancer(){
        return new CustomTokenEnhancer();
    }

}
```

这里做的最重要的两件事：**一是** 定义了两个客户端应用的通行证（`sheep1`和`sheep2`）；**二是** 配置 `token`的具体实现方式为 `JWT Token`。

- **Spring Security安全配置 `SpringSecurityConfig`**

```
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        authenticationProvider.setHideUserNotFoundExceptions(false);
        return authenticationProvider;
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .requestMatchers().antMatchers("/oauth/**","/login/**","/logout/**")
                .and()
                .authorizeRequests()
                .antMatchers("/oauth/**").authenticated()
                .and()
                .formLogin().permitAll();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }

}
```

---

## 客户端应用创建和配置

本文创建两个客户端应用：`codesheep-client1` 和`codesheep-client2`，`codesheep-client1`采用了`password`认证模式，`codesheep-client1`采用了授权模式，下面是他们的差异部分：

- **`codesheep-client1`客户端应用配置类 **

  ```java
  /**
   * 资源服务器
   */
  @Configuration
  @EnableResourceServer
  public class OAuth2ResourceServer extends ResourceServerConfigurerAdapter {
  
      @Override
      public void configure(HttpSecurity http) throws Exception {
          http.antMatcher("/**").authorizeRequests()
                  .anyRequest().authenticated();
      }
  }
  ```

* **`codesheep-client2`客户端应用配置类 **

  ```java
  @Configuration
  @EnableWebSecurity
  @EnableGlobalMethodSecurity(prePostEnabled = true)
  @EnableOAuth2Sso
  public class ClientWebsecurityConfigurer extends WebSecurityConfigurerAdapter {
  
      @Override
      public void configure(HttpSecurity http) throws Exception {
          http.antMatcher("/**").authorizeRequests()
                  .anyRequest().authenticated();
      }
  }
  ```

复杂的东西都交给注解了！

- **`codesheep-client1`的application.yml配置**

  ```yml
  server:
    port: 8086
  
  security:
    oauth2:
      resource:
        jwt:  #项目启动过程中，检查到配置文件中有security.oauth2.resource.jwt 的配置，就会生成 jwtTokenStore 的 bean，对令牌的校验就会使用 jwtTokenStore
          key-value: testKey   # 设置签名key 保持和授权服务器一致
  ```

- **`codesheep-client2`的application.yml配置**

```yml
auth-server: http://localhost:8085/uac
server:
  port: 8087

security:
  oauth2:
    client:
      client-id: sheep1
      client-secret: 123456
      user-authorization-uri: ${auth-server}/oauth/authorize
      access-token-uri: ${auth-server}/oauth/token
    resource:
      jwt:
        key-uri: ${auth-server}/oauth/token_key
```

这里几项配置都非常重要，都是需要和前面搭建的授权中心进行通信的

- **创建测试控制器 `TestController`**

```
@RestController
public class TestController {

    @GetMapping("/normal")
    @PreAuthorize("hasAuthority('ROLE_NORMAL')")
    public String normal( ) {
        return "normal permission test success !!!";
    }

    @GetMapping("/medium")
    @PreAuthorize("hasAuthority('ROLE_MEDIUM')")
    public String medium() {
        return "medium permission test success !!!";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String admin() {
        return "admin permission test success !!!";
    }
     /**
     * access_token解密
     * @param userDetails
     * @param authentication
     * @param request
     * @return
     */
    @GetMapping("/me")
    public Object getCurrentUser(@AuthenticationPrincipal UserDetails userDetails, Authentication authentication, HttpServletRequest request) throws UnsupportedEncodingException {
        // Authentication authentication1 = SecurityContextHolder.getContext().getAuthentication();
        // Authorization : bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
        // 增加了jwt之后，获取传递过来的token
        // 当然这里只是其中一种的 token的传递方法，自己要根据具体情况分析
        String authorization = request.getHeader("Authorization");
        String token = StringUtils.substringAfter(authorization, "bearer ");
        String jwtSigningKey = "testKey";
        // 生成的时候使用的是 org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
        // 源码里面把signingkey变成utf8了
        // JwtAccessTokenConverter类，解析出来是一个map
        // 所以这个自带的JwtAccessTokenConverter对象也是可以直接用来解析的
        byte[] bytes = jwtSigningKey.getBytes("utf-8");
        Claims body = Jwts.parser().setSigningKey(bytes).parseClaimsJws(token).getBody();

        return body;
    }
}
```

此测试控制器包含三个接口，分别需要三种权限（`ROLE_NORMAL`、`ROLE_MEDIUM`、`ROLE_ADMIN`），待会后文会一一测试看效果

---

## 实验验证

- 启动授权认证中心 `codesheep-server`（启动于本地`8085`端口）
- 启动客户端应用 `codesheep-client1` （启动于本地`8086`端口）
- 启动客户端应用 `codesheep-client2` （启动于本地`8087`端口）

首先用浏览器访问客户端1 (`codesheep-client1`) 的测试接口：`localhost:8086/normal`，由于此时并没有过用户登录认证，因此会自动跳转到授权中心的登录认证页面：`http://localhost:8085/uac/login`：

![自动跳转到授权中心统一登录页面](https://raw.githubusercontent.com/hansonwang99/pic/master/springbt_sso_jwt/自动跳转到授权中心统一登录页面.png)

输入用户名 `codesheep`，密码 `123456`，即可登录认证，并进入授权页面：

![授权页面](https://raw.githubusercontent.com/hansonwang99/pic/master/springbt_sso_jwt/授权页面.png)

同意授权后，会自动返回之前客户端的测试接口：

![自动返回客户端接口并调用成功](https://raw.githubusercontent.com/hansonwang99/pic/master/springbt_sso_jwt/自动返回客户端接口并调用成功.png)

此时我们再继续访问客户端1 (`codesheep-client1`) 的测试接口：`localhost:8086/medium`，发现已经直接可以调用而无需认证了：

![直接访问](https://raw.githubusercontent.com/hansonwang99/pic/master/springbt_sso_jwt/直接访问.png)

由于 `localhost:8086/normal` 和 `localhost:8086/medium`要求的接口权限，用户`codesheep`均具备，所以能顺利访问，接下来再访问一下更高权限的接口：`localhost:8086/admin`：

![无权限访问](https://raw.githubusercontent.com/hansonwang99/pic/master/springbt_sso_jwt/无权限访问.png)

好了，访问客户端1 (`codesheep-client1`) 的测试接口到此为止，接下来访问外挂的客户端2 (`codesheep-client2`) 的测试接口：`localhost:8087/normal`，会发现此时会自动跳到授权页：

![由于用户已通过客户端1登录过_因此再访问客户端2即无需登录_而是直接跳到授权页](https://raw.githubusercontent.com/hansonwang99/pic/master/springbt_sso_jwt/由于用户已通过客户端1登录过_因此再访问客户端2即无需登录_而是直接跳到授权页.png)

授权完成之后就可以顺利访问客户端2 (`codesheep-client2`) 的接口：

![顺利访问客户端2的接口](https://raw.githubusercontent.com/hansonwang99/pic/master/springbt_sso_jwt/顺利访问客户端2的接口.png)

这就验证了单点登录`SSO`的功能了！

---

## 测试中用到的命令
```$xslt
curl -X POST --user 'clientapp:123' -d 'grant_type=password&username=user&password=123456' http://localhost:8080/oauth/token

curl -X POST -H "authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NTQ0MzExMDgsInVzZXJfbmFtZSI6InVzZXIiLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiOGM0YWMyOTYtMDQwYS00Y2UzLTg5MTAtMWJmNjZkYTQwOTk3IiwiY2xpZW50X2lkIjoiY2xpZW50YXBwIiwic2NvcGUiOlsicmVhZCJdfQ.YAaSRN0iftmlR6Khz9UxNNEpHHn8zhZwlQrCUCPUmsU" -d 'name=zhangsan' http://localhost:8081/api/hi
```

### client1原来的配置文件
```$xslt
auth-server: http://localhost:8085/uac
server:
  port: 8086

security:
  oauth2:
    client:
      client-id: sheep1
      client-secret: 123456
      user-authorization-uri: ${auth-server}/oauth/authorize
      access-token-uri: ${auth-server}/oauth/token
    resource:
      jwt:
        key-value: testKey
```
https://jwt.io/
---