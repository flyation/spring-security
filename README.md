# Spring Security的使用
## 前置工作，准备Spring MVC的环境
## Spring Security的环境
1. 引入Spring Security的依赖
```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-web</artifactId>
    <version>4.2.10.RELEASE</version>
</dependency>

<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-config</artifactId>
    <version>4.2.10.RELEASE</version>
</dependency>

<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-taglibs</artifactId>
    <version>4.2.10.RELEASE</version>
</dependency>
```
2. 在`web.xml`中配置`DelegatingFilterProxy`
> filter-name必须是springSecurityFilterChain。因为 springSecurityFilterChain 在 IOC 容器中对应真正执行权限控制的二十几个 Filter，SpringSecurity会根据filter-name去IoC容器中找对应的bean，只有叫这个名字才能够加载到这些 Filter。
```xml
    <!-- SpringSecurity 控制权限的 Filter -->
    <filter>
        <filter-name>springSecurityFilterChain</filter-name>
        <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
    </filter>
    <filter-mapping>
        <filter-name>springSecurityFilterChain</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
```
3. 创建配置类，需要继承WebSecurityConfigurerAdapter

   1. 需要添加注解

      - @Configuratio： 声明配置类
      - @EnableWebSecurity：启用web下的权限控制
   2. 重写两个方法
       - configure(AuthenticationManagerBuilder auth)：与Spring Security环境下用户登录相关
       - configure(HttpSecurity http) ：与Spring Security环境下请求授权相关
