package com.best.hello;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;

/* Spring Boot 启动类 */
@SpringBootApplication
@ServletComponentScan
public class HelloApplication {

    /* main方法，程序执行入口 */
    public static void main(String[] args) {
        SpringApplication.run(HelloApplication.class, args);
    }

}
