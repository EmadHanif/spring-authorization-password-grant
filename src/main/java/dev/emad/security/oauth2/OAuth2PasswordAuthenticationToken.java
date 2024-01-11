package dev.emad.security.oauth2;

import java.util.Map;
import java.util.Set;
import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

/**
 * @author EmadHanif
 */
@Getter
public class OAuth2PasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

  private final String username;
  private final String password;
  private final Set<String> scopes;

  protected OAuth2PasswordAuthenticationToken(
      Authentication clientPrincipal,
      Map<String, Object> additionalParameters,
      Set<String> scopes) {
    super(AuthorizationGrantType.PASSWORD, clientPrincipal, additionalParameters);
    this.username = (String) additionalParameters.get("username");
    this.password = (String) additionalParameters.get("password");
    this.scopes = scopes;
  }
}
