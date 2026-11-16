package dev.emad.core.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.Set;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * @author EmadHanif
 */
@Validated
@ConfigurationProperties("config")
public record SpringConfigProperties(
    @NotNull @Valid Database database,
    @NotNull @Valid Security security,
    @NotNull @Valid JwtKeyStore jwtKeyStore) {

  public record Database(@NotBlank String host, @NotBlank String username, @NotBlank String password) {}

  public record Security(
      @NotNull  Set<String> redirectUris,
      @NotBlank String tokenEndpoint,
      @NotBlank String issuer,
      @NotNull Set<String> cors) {}

  public record JwtKeyStore(
      @NotBlank String jksLocation, @NotBlank String password, @NotBlank String alias) {}
}
