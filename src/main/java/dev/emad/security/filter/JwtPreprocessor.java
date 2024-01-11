package dev.emad.security.filter;

import dev.emad.entities.User;
import dev.emad.exceptions.ErrorMessage;
import dev.emad.utils.JsonHelper;
import dev.emad.utils.StringHelper;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * @author EmadHanif
 */
@Component
public class JwtPreprocessor extends OncePerRequestFilter {

  @Autowired private JwtDecoder jwtDecoder;
  @Autowired private OAuth2AuthorizationService authorizationService;

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest req,
      @NonNull HttpServletResponse res,
      @NonNull FilterChain filterChain)
      throws ServletException, IOException {

    String token = extractToken(req);
    if (StringHelper.hasText(token)) {

      try {

        OAuth2Authorization oAuth2Authorization =
            this.authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);

        Assert.notNull(oAuth2Authorization, "Token doesn't exist.");

        Jwt decode = jwtDecoder.decode(token);
        Map<String, Object> claims = decode.getClaims();

        String email = decode.getSubject();
        String id = (String) claims.get("id");
        String fullName = (String) claims.get("name");

        List<String> authorities =
            (List<String>) claims.getOrDefault("authorities", Collections.emptyList());

        Set<SimpleGrantedAuthority> authoritySet =
            authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());

        User user = new User();
        user.setId(UUID.fromString(id));
        user.setEmail(email);
        user.setFullName(fullName);

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
            new UsernamePasswordAuthenticationToken(user, null, authoritySet);

        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

      } catch (final Exception e) {
        ErrorMessage errorResponse = new ErrorMessage(e.getMessage(), LocalDateTime.now());
        res.setContentType(MediaType.APPLICATION_JSON_VALUE);
        res.getWriter().print(JsonHelper.convertToString(errorResponse));
        res.setStatus(HttpStatus.UNAUTHORIZED.value());
        return;
      }
    }

    filterChain.doFilter(req, res);
  }

  public static String extractToken(HttpServletRequest request) {
    String header = request.getHeader("Authorization");
    if (Objects.nonNull(header) && header.startsWith("Bearer"))
      return header.replace("Bearer ", "");

    return null;
  }
}
