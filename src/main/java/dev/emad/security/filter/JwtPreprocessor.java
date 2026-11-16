package dev.emad.security.filter;

import dev.emad.entities.User;
import dev.emad.helper.JsonHelper;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.net.URI;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
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
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * @author EmadHanif
 */
@Component
@RequiredArgsConstructor
public class JwtPreprocessor extends OncePerRequestFilter {

  private final JwtDecoder jwtDecoder;
  private final OAuth2AuthorizationService authorizationService;

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest req, @NonNull HttpServletResponse res, @NonNull FilterChain filterChain)
      throws ServletException, IOException {

    String token = extractToken(req);
    if (StringUtils.hasText(token)) {

      try {
        OAuth2Authorization oAuth2Authorization =
            this.authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);

        Assert.notNull(oAuth2Authorization, "Token invalid or revoked.");

        Jwt decode = jwtDecoder.decode(token);
        Map<String, Object> claims = decode.getClaims();

        String email = decode.getSubject();
        Long id = (Long) claims.get("id");
        String fullName = (String) claims.get("name");

        List<String> authorities = (List<String>) claims.getOrDefault("authorities", Collections.emptyList());

        Set<SimpleGrantedAuthority> authoritySet =
            authorities.isEmpty()
                ? Collections.emptySet()
                : authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());

        User user = new User();
        user.setId(id);
        user.setEmail(Objects.requireNonNull(email));
        user.setFullName(fullName);
        user.setAuthorities(authoritySet);

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
            new UsernamePasswordAuthenticationToken(user, null, authoritySet);

        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

      } catch (final Exception ex) {

        // Optional (a good prc)
        SecurityContextHolder.clearContext();

        ProblemDetail problemDetail =
            ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Invalid or expired access token.");

        problemDetail.setTitle("Unauthorized");
        problemDetail.setInstance(URI.create(req.getRequestURI()));
        problemDetail.setProperty("timestamp", LocalDateTime.now());

        res.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        res.setStatus(HttpStatus.UNAUTHORIZED.value());

        JsonHelper.writeTo(res.getOutputStream(), problemDetail);
        return;
      }
    }

    filterChain.doFilter(req, res);
  }

  public static String extractToken(HttpServletRequest request) {
    String header = request.getHeader("Authorization");
    return (header != null && header.startsWith("Bearer ")) ? header.substring(7) : null;
  }
}
