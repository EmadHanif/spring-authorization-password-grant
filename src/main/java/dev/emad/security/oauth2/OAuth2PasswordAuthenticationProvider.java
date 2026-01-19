package dev.emad.security.oauth2;

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
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

  public static final String ERROR_URI =
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
  public Authentication authenticate(@NonNull Authentication authentication)
      throws AuthenticationException {

    // Parse Authentication to OAuth2PasswordAuthenticationToken
    OAuth2PasswordAuthenticationToken authenticationToken =
        (OAuth2PasswordAuthenticationToken) authentication;

    OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClient(authentication);
    RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

    Assert.notNull(registeredClient, "The registered client is null.");

    Authentication usernamePasswordAuthentication =
        getUsernamePasswordAuthentication(authenticationToken);

    // Extract authorized scopes from OAuth2PasswordAuthenticationToken
    Set<String> authorizedScopes =
        new HashSet<>(
            authenticationToken.getScopes() != null
                ? authenticationToken.getScopes()
                : Collections.emptySet());

    // Validate requested scopes against registered client scopes
    authorizedScopes.retainAll(registeredClient.getScopes());

    if (authorizedScopes.isEmpty()) {
      OAuth2Error error =
          new OAuth2Error(
              OAuth2ErrorCodes.INVALID_SCOPE,
              "The requested scope is invalid, unknown, or malformed.",
              ERROR_URI);
      throw new OAuth2AuthenticationException(error);
    }

    // Token Context Builder
    DefaultOAuth2TokenContext.Builder tokenContextBuilder =
        DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(usernamePasswordAuthentication)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .authorizedScopes(authorizedScopes)
            .authorizationGrantType(new AuthorizationGrantType("password"))
            .authorizationGrant(authenticationToken);

    OAuth2Authorization.Builder authorizationBuilder =
        OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName(usernamePasswordAuthentication.getName())
            .authorizationGrantType(new AuthorizationGrantType("password"))
            .authorizedScopes(authorizedScopes)
            .attribute(Principal.class.getName(), usernamePasswordAuthentication);

    // AccessToken
    OAuth2TokenContext tokenContext =
        tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();

    OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);

    if (Objects.isNull(generatedAccessToken)) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(
              OAuth2ErrorCodes.SERVER_ERROR, "Failed to generate access token.", ERROR_URI));
    }

    OAuth2AccessToken accessToken =
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.getTokenValue(),
            generatedAccessToken.getIssuedAt(),
            generatedAccessToken.getExpiresAt(),
            authorizedScopes);

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

      if (Objects.isNull(generatedRefreshToken)
          || !(generatedRefreshToken instanceof OAuth2RefreshToken)) {
        throw new OAuth2AuthenticationException(
            new OAuth2Error(
                OAuth2ErrorCodes.SERVER_ERROR, "Failed to generate refresh token.", ERROR_URI));
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
  public boolean supports(@NonNull Class<?> authentication) {
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
    throw new OAuth2AuthenticationException(
        new OAuth2Error(
            OAuth2ErrorCodes.INVALID_CLIENT, "The client is not authenticated", ERROR_URI));
  }

  private Authentication getUsernamePasswordAuthentication(
      OAuth2PasswordAuthenticationToken authenticationToken) {

    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
        new UsernamePasswordAuthenticationToken(
            authenticationToken.getUsername(), authenticationToken.getPassword());

    return this.authenticationManager.authenticate(usernamePasswordAuthenticationToken);
  }
}
