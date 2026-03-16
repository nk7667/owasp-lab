package org.owasplab;

import org.mybatis.spring.annotation.MapperScan;
import org.owasplab.coach.llm.CoachLlmProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(CoachLlmProperties.class)
@MapperScan("org.owasplab.mapper")
public class OwaspLabApplication {
    public static void main(String[] args) {
       SpringApplication.run(OwaspLabApplication.class, args);
    }
}