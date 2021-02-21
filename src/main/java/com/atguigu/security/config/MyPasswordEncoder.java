package com.atguigu.security.config;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

@Component
public class MyPasswordEncoder implements PasswordEncoder {
    @Override
    public String encode(CharSequence rawPassword) {
        return privateEncode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        // 1.对明文进行加密
        String formPassword = privateEncode(rawPassword);
        // 2.声明数据库中存储的密码
        String databasePassword = encodedPassword;
        // 3.比较两者
        return Objects.equals(formPassword, databasePassword);
    }

    private String privateEncode(CharSequence rawPassword) {
        try {
            // 1.创建messageDigest
            String algorithm = "md5";
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            // 2.获取输入的字节数组
            byte[] input = ((String) rawPassword).getBytes();
            // 3.加密
            byte[] output = messageDigest.digest(input);
            // 4.转换为对应的16位字符（signum为1表示转换为正数）
            String encoded = new BigInteger(1, output).toString(16).toUpperCase();
            return encoded;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        System.out.println(new MyPasswordEncoder().encode("123123"));
    }
}
