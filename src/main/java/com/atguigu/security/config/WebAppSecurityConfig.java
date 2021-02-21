package com.atguigu.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;

// 声明配置类
@Configuration
// 启用web下的权限控制
@EnableWebSecurity
// 用Spring Security要继承WebSecurityConfigurerAdapter，注意：这个类一定要放在自动扫描的包中，否则不会生效
public class WebAppSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    /**
     * 自己写的userDetailsService
     */
    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * 自己写的passwordEncoder
     */
//    @Autowired
//    private PasswordEncoder passwordEncoder;

    /**
     * Spring Security提供的bCryptPasswordEncoder。
     * 因为bean默认为单例，所以每次调用这个方法时会先去IoC中检查是否已存在这个对象，若存在则直接使用那个对象，不会真正执行这个函数。
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder builder) throws Exception {
//        builder
//                .inMemoryAuthentication()        // 在内存中完成账号密码的检查
//                .withUser("tom")        // 指定账号
//                .password("123123")              // 指定密码
//                .roles("ADMIN", "学徒")           // 指定当前用户的角色
//                .and()
//                .withUser("jerry")       // 指定账号
//                .password("123123")               // 指定密码
//                .authorities("UPDATE", "内门弟子") // 指定当前用户的权限
//                ;

        builder
                .userDetailsService(userDetailsService) // 用自己写的userDetailsService做登录检查
                .passwordEncoder(bCryptPasswordEncoder())       // 用自己写的passwordEncoder进行密码加密
                ;
    }

    @Override
    protected void configure(HttpSecurity security) throws Exception {

        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);

        security
                .authorizeRequests()                  // 对请求进行授权
                .antMatchers("/index.jsp") // 针对/index.jsp进行授权
                .permitAll()                          // 可以无条件访问
                .antMatchers("/layui/**")  // 针对/layui目录下所有资源进行授权
                .permitAll()                          // 可以无条件访问
                .antMatchers("/level1/**") // 针对/level1目录下所有资源进行授权
                .hasRole("学徒")                       // 需要有学徒角色
                .antMatchers("/level2/**") // 针对/level2目录下所有资源进行授权
                .hasAuthority("内门弟子")                  // 需要有学徒权限
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
//                .csrf()                             // CSRF指跨站请求伪造
//                .disable()                          // 禁用CSRF
                .logout()
                .logoutUrl("/do/logout.html")         // 退出登录地址
                .logoutSuccessUrl("/index.jsp")       // 退出登录成功后前往的地址
                .and()
                .exceptionHandling()                  // 指定异常处理器
//                .accessDeniedPage("/to/no/auth/page.html") // 403（访问被拒绝）前往的页面
                .accessDeniedHandler(new AccessDeniedHandler() {    // 自定义403处理器（自己写代码）
                    @Override
                    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
                        httpServletRequest.setAttribute("message", "走错门了吗？");
                        httpServletRequest.getRequestDispatcher("/WEB-INF/views/no_auth.jsp").forward(httpServletRequest, httpServletResponse);
                    }
                })
                .and()
                .rememberMe()                         // 开启“记住我”（表单默认参数名为remember-me），若需更改，调用rememberMeParameter
                .tokenRepository(tokenRepository)   // 开启令牌
                ;
    }
}
