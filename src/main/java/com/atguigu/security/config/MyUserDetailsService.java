package com.atguigu.security.config;

import com.atguigu.security.entity.Admin;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * 根据表单提交的账号查询User对象。
     * 并装配角色、权限信息
     * @param s 表单提交的用户名
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        // 1.查询数据库
        String sql = "select * from t_admin where loginacct = ?";
        List<Admin> list = jdbcTemplate.query(sql, new BeanPropertyRowMapper<>(Admin.class), s);
        Admin admin = list.get(0);

        // 设置角色、权限信息
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));  // ADMIN角色
        authorities.add(new SimpleGrantedAuthority("UPDATE"));      // UPDATE权限

        // 装配admin和角色、权限信息
        User user = new User(s, admin.getUserPswd(), authorities);
        return user;
    }
}
