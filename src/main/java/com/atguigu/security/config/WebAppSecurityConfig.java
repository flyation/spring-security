package com.atguigu.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

// 声明配置类
@Configuration
// 启用web下的权限控制
@EnableWebSecurity
// 用Spring Security要继承WebSecurityConfigurerAdapter，注意：这个类一定要放在自动扫描的包中，否则不会生效
public class WebAppSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder builder) throws Exception {
        builder
                .inMemoryAuthentication()        // 在内存中完成账号密码的坚持
                .withUser("tom")        // 指定账号
                .password("123123")              // 指定密码
                .roles("ADMIN")                 // 指定当前用户的角色
                .and()
                .withUser("jerry")        // 指定账号
                .password("123123")              // 指定密码
                .authorities("UPDATE")                 // 指定当前用户的权限
                ;
    }

    @Override
    protected void configure(HttpSecurity security) throws Exception {
        security
                .authorizeRequests()                  // 对请求进行授权
                .antMatchers("/index.jsp") // 针对/index.jsp进行授权
                .permitAll()                          // 可以无条件访问
                .antMatchers("/layui/**")  // 针对/layui目录下所有资源进行授权
                .permitAll()                          // 可以无条件访问
                .and()
                .authorizeRequests()                  // 授权
                .anyRequest()                         // 针对其他资源进行授权
                .authenticated()                      // 需要认证后才能访问
                .and()
                .formLogin()                          // 使用表单形式登录
                // loginPage方法的特殊说明：指定登录页的同时会影响到“提交登录表单的地址” “登陆失败的地址” “退出登录地址”
                .loginPage("/index.jsp")              // 指定登录页面（若不指定则跳转到Spring Security默认登陆页面）
                // loginProcessingUrl：设置了该方法就会覆盖loginPage方法中设置的默认值/index.jsp POST
                .loginProcessingUrl("/do/login.html") // 指定提交登录表单的地址
                .usernameParameter("loginAcct")       // 设置登录账号的参数名（若不设置，默认为username）
                .passwordParameter("userPswd")        // 设置登录 密码的参数名（若不设置，默认为password）
                .defaultSuccessUrl("/main.html")      // 登录成功后默认前往的地址
                .and()
//                .csrf()                                 // CSRF指跨站请求伪造
//                .disable()                              // 禁用CSRF
                .logout()
                .logoutUrl("/do/logout.html")           // 退出登录地址
                .logoutSuccessUrl("/index.jsp")         // 退出登录成功后前往的地址
                ;
    }
}
