package dev.emad.security.mixin;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author EmadHanif
 */
public abstract class UUIDMixin {

  @JsonCreator
  public UUIDMixin(@JsonProperty("id") String id) {}
}
