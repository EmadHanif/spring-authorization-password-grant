package dev.emad.security.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import java.util.*;

import org.jspecify.annotations.NonNull;
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
  public Authentication convert(@NonNull HttpServletRequest request) {

    String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

    // Early-exit if the grant_type is not password
    // Return null instead of throwing; let other converters try
    if (!GRANT_TYPE_PASSWORD.equals(grantType)) {
      return null;
    }

    MultiValueMap<String, String> parameters = getParameters(request);

    // Validate required parameters (username, password, scope)
    Map<String, String> params =
        validateRequiredParameters(
            parameters, PARAMETER_USERNAME, PARAMETER_PASSWORD, OAuth2ParameterNames.SCOPE);

    // Parse scopes - use space " " as delimiter (OAuth2 spec)
    Set<String> scopes =
        new HashSet<>(
            Arrays.asList(
                StringUtils.delimitedListToStringArray(
                    params.get(OAuth2ParameterNames.SCOPE), " ")));

    Map<String, Object> additionalParameters = new HashMap<>();
    parameters.forEach(
        (key, value) -> {
          if (!key.equals(OAuth2ParameterNames.GRANT_TYPE)
              && !key.equals(OAuth2ParameterNames.SCOPE)) {
            additionalParameters.put(key, value.getFirst());
          }
        });

    Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
    return new OAuth2PasswordAuthenticationToken(clientPrincipal, additionalParameters, scopes);
  }

  public static Map<String, String> validateRequiredParameters(
      MultiValueMap<String, String> parameters, String... requiredParameters) {

    Map<String, String> validatedValues = new HashMap<>();

    for (String param : requiredParameters) {
      List<String> values = parameters.get(param);

      if (values == null || values.size() != 1 || !StringUtils.hasText(values.getFirst())) {
        throw new OAuth2AuthenticationException(
            new OAuth2Error(
                OAuth2ErrorCodes.INVALID_REQUEST,
                "The '" + param + "' parameter is required and must appear exactly once.",
                OAuth2PasswordAuthenticationProvider.ERROR_URI));
      }

      validatedValues.put(param, values.getFirst());
    }

    return validatedValues;
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
