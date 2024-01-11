package dev.emad.configuration;

import jakarta.validation.constraints.NotBlank;
import java.util.Set;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

/**
 * @author EmadHanif
 */
@Validated
@Component
@Getter
@ConfigurationProperties("config")
public class SpringConfigProperties {

  private final Security security = new Security();
  private final DatabaseConfig databaseConfig = new DatabaseConfig();

  @Getter
  @Setter
  public static class DatabaseConfig {
    @NotBlank private String host;
    @NotBlank private String username;
    @NotBlank private String password;
  }

  @Getter
  @Setter
  public static class Security {
    @NotBlank private String redirectUris;
    @NotBlank private String tokenEndpoint;
    @NotBlank private String issuer;
    @NotBlank private String cors;
  }
}
