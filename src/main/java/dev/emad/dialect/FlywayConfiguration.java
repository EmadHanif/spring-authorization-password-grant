package dev.emad.dialect;

import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author EmadHanif
 */
@Configuration
public class FlywayConfiguration {

  @Autowired private DataSource dataSource;

  @Bean(initMethod = "migrate")
  public Flyway flyway() {

    Flyway flyway =
        Flyway.configure()
            .dataSource(dataSource)
            .locations("classpath:db/migration")
            .baselineOnMigrate(true)
            .schemas("public")
            .validateMigrationNaming(true)
            .load();

    flyway.repair();

    return flyway;
  }
}
