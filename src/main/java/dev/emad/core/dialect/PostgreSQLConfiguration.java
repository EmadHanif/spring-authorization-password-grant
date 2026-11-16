package dev.emad.core.dialect;

import com.zaxxer.hikari.HikariDataSource;
import dev.emad.core.properties.SpringConfigProperties;
import javax.sql.DataSource;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author EmadHanif
 */
@Configuration
public class PostgreSQLConfiguration {

  @Bean
  public DataSource dataSource(SpringConfigProperties properties) {

    return DataSourceBuilder.create()
        .type(HikariDataSource.class)
        .url(properties.database().host())
        .driverClassName("org.postgresql.Driver")
        .username(properties.database().username())
        .password(properties.database().password())
        .build();
  }
}
