package dev.emad.dialect;

import com.zaxxer.hikari.HikariDataSource;
import javax.sql.DataSource;

import dev.emad.configuration.SpringConfigProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author EmadHanif
 */
@Configuration
public class PostgreSQLConfiguration {

  @Bean
  public DataSource dataSource(SpringConfigProperties springConfigProperties) {

    return DataSourceBuilder.create()
        .type(HikariDataSource.class)
        .url(springConfigProperties.getDatabaseConfig().getHost())
        .driverClassName("org.postgresql.Driver")
        .username(springConfigProperties.getDatabaseConfig().getUsername())
        .password(springConfigProperties.getDatabaseConfig().getPassword())
        .build();
  }
}
