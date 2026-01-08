package dev.emad.security.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * @author EmadHanif
 */
public class OAuth2PasswordAuthenticationConverter implements AuthenticationConverter {

  private static final String PARAMETER_USERNAME = "username";
  private static final String PARAMETER_PASSWORD = "password";
  private static final String GRANT_TYPE_PASSWORD = "password";

  @Override
  public Authentication convert(HttpServletRequest request) {

    String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

    // Early exit for non-password grant types
    if (!GRANT_TYPE_PASSWORD.equals(grantType)) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE),
          "The grant type is not supported.");
    }

    MultiValueMap<String, String> parameters = getParameters(request);

    // username (mandatory, single-valued)
    String username = parameters.getFirst(PARAMETER_USERNAME);
    if (!StringUtils.hasText(username)
        || parameters.get(PARAMETER_USERNAME) == null
        || parameters.get(PARAMETER_USERNAME).size() != 1) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(
              OAuth2ErrorCodes.INVALID_REQUEST,
              "The 'username' parameter is required and must appear exactly once.",
              null));
    }

    // password (mandatory, single-valued)
    String password = parameters.getFirst(PARAMETER_PASSWORD);
    if (!StringUtils.hasText(password)
        || parameters.get(PARAMETER_PASSWORD) == null
        || parameters.get(PARAMETER_PASSWORD).size() != 1) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(
              OAuth2ErrorCodes.INVALID_REQUEST,
              "The 'password' parameter is required and must appear exactly once.",
              null));
    }

    // scope (mandatory, single-valued)
    String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
    if (!StringUtils.hasText(scope)
        || parameters.get(OAuth2ParameterNames.SCOPE) == null
        || parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(
              OAuth2ErrorCodes.INVALID_REQUEST,
              "The 'scope' parameter is required and must appear exactly once.",
              null));
    }

    Set<String> requestedScopes =
        new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));

    Map<String, Object> additionalParameters = new HashMap<>();
    parameters.forEach(
        (key, value) -> {
          if (!key.equals(OAuth2ParameterNames.GRANT_TYPE)
              && !key.equals(OAuth2ParameterNames.SCOPE)) {
            additionalParameters.put(key, value.getFirst());
          }
        });

    Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
    return new OAuth2PasswordAuthenticationToken(
        clientPrincipal, additionalParameters, requestedScopes);
  }

  private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
    Map<String, String[]> parameterMap = request.getParameterMap();
    MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
    parameterMap.forEach(
        (key, values) -> {
          for (String value : values) {
            parameters.add(key, value);
          }
        });
    return parameters;
  }
}
