package dev.emad.security.oauth2;

import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

/**
 * @author EmadHanif
 */
public class OAuth2PasswordAuthenticationProvider implements AuthenticationProvider {

  private static final String ERROR_URI =
      "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
  private final OAuth2AuthorizationService authorizationService;
  private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
  private final AuthenticationManager authenticationManager;

  public OAuth2PasswordAuthenticationProvider(
      AuthenticationManager authenticationManager,
      OAuth2AuthorizationService oAuth2AuthorizationService,
      OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {

    this.authenticationManager = authenticationManager;
    this.authorizationService = oAuth2AuthorizationService;
    this.tokenGenerator = tokenGenerator;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    OAuth2PasswordAuthenticationToken authenticationToken =
        (OAuth2PasswordAuthenticationToken) authentication;

    OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClient(authentication);
    RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

    Assert.notNull(registeredClient, "RegisteredClient cannot be null.");

    Authentication usernamePasswordAuthentication =
        getUsernamePasswordAuthentication(authenticationToken);

    Set<String> authorizedScopes =
        Optional.of(authenticationToken.getAuthorities()).orElse(Collections.emptySet()).stream()
            .map(GrantedAuthority::getAuthority)
            .filter(scope -> registeredClient.getScopes().contains(scope))
            .collect(Collectors.toSet());

    // Token Context Builder
    DefaultOAuth2TokenContext.Builder tokenContextBuilder =
        DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(usernamePasswordAuthentication)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .authorizedScopes(authorizedScopes)
            .authorizationGrantType(AuthorizationGrantType.PASSWORD)
            .authorizationGrant(authenticationToken);

    OAuth2Authorization.Builder authorizationBuilder =
        OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName(usernamePasswordAuthentication.getName())
            .authorizationGrantType(AuthorizationGrantType.PASSWORD)
            .authorizedScopes(authorizedScopes)
            .attribute(Principal.class.getName(), usernamePasswordAuthentication);

    // AccessToken...
    OAuth2TokenContext tokenContext =
        tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
    OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
    if (Objects.isNull(generatedAccessToken)) {
      OAuth2Error error =
          new OAuth2Error(
              OAuth2ErrorCodes.SERVER_ERROR,
              "An error occurred while attempting to generate access token.",
              ERROR_URI);
      throw new OAuth2AuthenticationException(error);
    }

    // AccessToken
    OAuth2AccessToken accessToken =
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.getTokenValue(),
            generatedAccessToken.getIssuedAt(),
            generatedAccessToken.getExpiresAt(),
            tokenContext.getAuthorizedScopes());

    authorizationBuilder.token(
        accessToken,
        (metadata) ->
            metadata.put(
                OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                ((ClaimAccessor) generatedAccessToken).getClaims()));

    // RefreshToken
    OAuth2RefreshToken refreshToken = null;
    if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)
        && !clientPrincipal
            .getClientAuthenticationMethod()
            .equals(ClientAuthenticationMethod.NONE)) {

      tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
      OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);

      if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
        OAuth2Error error =
            new OAuth2Error(
                OAuth2ErrorCodes.SERVER_ERROR,
                "An error occurred while attempting to generate refresh_token",
                ERROR_URI);
        throw new OAuth2AuthenticationException(error);
      }
      refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
      authorizationBuilder.refreshToken(refreshToken);
    }

    OAuth2Authorization authorization = authorizationBuilder.build();
    this.authorizationService.save(authorization);

    return new OAuth2AccessTokenAuthenticationToken(
        registeredClient, clientPrincipal, accessToken, refreshToken);
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return OAuth2PasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }

  private static OAuth2ClientAuthenticationToken getAuthenticatedClient(
      Authentication authentication) {

    Object principal = authentication.getPrincipal();

    if (principal instanceof OAuth2ClientAuthenticationToken clientPrincipal) {
      if (clientPrincipal.isAuthenticated()) {
        return clientPrincipal;
      }
    }
    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
  }

  private Authentication getUsernamePasswordAuthentication(
      OAuth2PasswordAuthenticationToken oAuth2PasswordAuthenticationToken) {

    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
        new UsernamePasswordAuthenticationToken(
            oAuth2PasswordAuthenticationToken.getUsername(),
            oAuth2PasswordAuthenticationToken.getPassword());

    return this.authenticationManager.authenticate(usernamePasswordAuthenticationToken);
  }
}
