package dev.emad.security.mixin;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.UUID;

/**
 * @author EmadHanif
 */
public abstract class UserMixin {

  @JsonCreator
  public UserMixin(
      @JsonProperty("id") UUID id,
      @JsonProperty("password") String password,
      @JsonProperty("email") String email) {}
}
