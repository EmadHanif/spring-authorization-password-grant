package dev.emad;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

import java.time.LocalDateTime;
import java.util.TimeZone;

/*
 @author EmadHanif
*/
@SpringBootApplication
@Slf4j
public class SpringAuthorizationApplication {

  public static void main(String[] args) {
    new SpringApplicationBuilder(SpringAuthorizationApplication.class).run(args);
  }

  @PostConstruct
  public void init() {
    // Set default timezone to UTC
    TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
    log.info("Spring Boot application running in UTC timezone: {}", LocalDateTime.now());
  }
}
