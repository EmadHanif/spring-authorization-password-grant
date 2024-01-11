package dev.emad.security.config;

import static org.springframework.security.config.Customizer.withDefaults;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.io.File;
import java.security.KeyStore;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

import dev.emad.configuration.JwtKeyStoreProperties;
import dev.emad.configuration.SpringConfigProperties;
import dev.emad.entities.User;
import dev.emad.security.filter.JwtAuthenticationEntryPoint;
import dev.emad.security.mixin.UUIDMixin;
import dev.emad.security.mixin.UserMixin;
import dev.emad.security.oauth2.OAuth2PasswordAuthenticationConverter;
import dev.emad.security.oauth2.OAuth2PasswordAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author EmadHanif
 */
@EnableWebSecurity
@EnableMethodSecurity
@Configuration
public class AuthenticationServerConfig {

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain asSecurityFilterChain(
      HttpSecurity http,
      AuthenticationManager authenticationManager,
      OAuth2AuthorizationService authorizationService,
      OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
      JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint)
      throws Exception {

    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        .tokenEndpoint(
            tokenEndpoint ->
                tokenEndpoint
                    .accessTokenRequestConverter(
                        new DelegatingAuthenticationConverter(
                            Arrays.asList(
                                new OAuth2AuthorizationCodeAuthenticationConverter(),
                                new OAuth2RefreshTokenAuthenticationConverter(),
                                new OAuth2ClientCredentialsAuthenticationConverter(),
                                new OAuth2PasswordAuthenticationConverter())))
                    .authenticationProvider(
                        new OAuth2PasswordAuthenticationProvider(
                            authenticationManager, authorizationService, tokenGenerator)));
    return http.formLogin(withDefaults())
        .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
        .exceptionHandling(
            exceptionHandling ->
                exceptionHandling.authenticationEntryPoint(jwtAuthenticationEntryPoint))
        .build();
  }

  @Bean
  public AuthenticationManager authenticationManager(
      List<AuthenticationProvider> authenticationProviders) {
    return new ProviderManager(authenticationProviders);
  }

  @Bean
  public DaoAuthenticationProvider authenticationProvider(
      UserDetailsService userDetailsService, PasswordEncoder encoder) {
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService);
    authProvider.setPasswordEncoder(encoder);
    return authProvider;
  }

  @Bean
  public OAuth2AuthorizationService authorizationService(
      JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {

    JdbcOAuth2AuthorizationService authorizationService =
        new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);

    ObjectMapper objectMapper = new ObjectMapper();
    objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    objectMapper.configure(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES, false);
    objectMapper.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);

    ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();

    objectMapper.registerModules(SecurityJackson2Modules.getModules(classLoader));
    objectMapper.registerModule(new CoreJackson2Module());
    objectMapper.registerModule(new JavaTimeModule());
    objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    objectMapper.registerModule(new ParameterNamesModule());
    objectMapper.registerModule(new Jdk8Module());

    objectMapper.addMixIn(UUID.class, UUIDMixin.class);
    objectMapper.addMixIn(User.class, UserMixin.class);

    JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper rowMapper =
        new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(registeredClientRepository);
    rowMapper.setObjectMapper(objectMapper);
    authorizationService.setAuthorizationRowMapper(rowMapper);
    return authorizationService;
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations) {
    return new JdbcRegisteredClientRepository(jdbcOperations);
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public TokenSettings tokenSettings() {
    return TokenSettings.builder()
        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
        .accessTokenTimeToLive(Duration.ofHours(24))
        .reuseRefreshTokens(false)
        .refreshTokenTimeToLive(Duration.ofDays(30))
        .build();
  }

  @Bean
  public ClientSettings clientSettings() {
    return ClientSettings.builder().build();
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings(
      SpringConfigProperties springConfigProperties) {
    return AuthorizationServerSettings.builder()
        .issuer(springConfigProperties.getSecurity().getIssuer())
        .tokenEndpoint(
            springConfigProperties.getSecurity().getTokenEndpoint()) // Your desired endpoint
        .build();
  }

  @Bean
  public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(
      OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer,
      JWKSource<SecurityContext> jwkSource) {
    NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
    JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
    jwtGenerator.setJwtCustomizer(tokenCustomizer);
    OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
    OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
    return new DelegatingOAuth2TokenGenerator(
        jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
  }

  /**
   * Replacement of TokenEnhancer
   *
   * @return OAuth2TokenCustomizer
   */
  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
    return context -> {
      Authentication authentication = context.getPrincipal();

      UsernamePasswordAuthenticationToken authenticationToken = context.getPrincipal();

      if (authenticationToken.getPrincipal() instanceof User) {

        User user = (User) authentication.getPrincipal();

        Set<String> authorities =
            Optional.of(authenticationToken.getAuthorities())
                .orElse(Collections.emptySet())
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        if (context.getTokenType().getValue().equals("access_token")) {
          context
              .getClaims()
              .claim("authorities", authorities)
              .claim("id", user.getId())
              .claim("name", user.getFullName());
        }
      }
    };
  }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource(JWKSet jwkSet) {
    return (jwkSelector, securityContext) -> {
      try {
        return jwkSelector.select(jwkSet);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    };
  }

  @Bean
  public JWKSet jwkSet(JwtKeyStoreProperties jwtKeyStoreProperties) throws Exception {

    String keyAlias = jwtKeyStoreProperties.getKeypairAlias();
    File file = new ClassPathResource(jwtKeyStoreProperties.getJksLocation()).getFile();
    char[] keyPass = jwtKeyStoreProperties.getPassword().toCharArray();

    KeyStore keyStore =
        KeyStore.Builder.newInstance(file, new KeyStore.PasswordProtection(keyPass)).getKeyStore();

    RSAKey rsaKey = RSAKey.load(keyStore, keyAlias, keyPass);

    return new JWKSet(rsaKey);
  }
}
