package dev.emad.security.config;

import java.util.Arrays;
import java.util.List;

import dev.emad.configuration.SpringConfigProperties;
import dev.emad.security.filter.JwtAuthenticationEntryPoint;
import dev.emad.security.filter.JwtPreprocessor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

/**
 * @author EmadHanif
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class ResourceServerConfig {

  private final JwtPreprocessor jwtPreprocessor;

  private final SpringConfigProperties springConfigProperties;

  public ResourceServerConfig(
      JwtPreprocessor jwtPreprocessor, SpringConfigProperties springConfigProperties) {
    this.jwtPreprocessor = jwtPreprocessor;
    this.springConfigProperties = springConfigProperties;
  }

  @Bean
  public SecurityFilterChain asResourceFilterChain(
      HttpSecurity http,
      JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
      CorsConfigurationSource corsConfiguration)
      throws Exception {
    return http.authorizeHttpRequests(
            auth ->
                auth.requestMatchers(HttpMethod.GET, "/v1/examples/m1")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .sessionManagement(
            sessionConfigurer ->
                sessionConfigurer.sessionCreationPolicy(
                    SessionCreationPolicy.STATELESS)) // session stateless.
        .csrf(AbstractHttpConfigurer::disable) // disabling csrf,
        .cors(cors -> cors.configurationSource(corsConfiguration))
        .addFilterBefore(jwtPreprocessor, UsernamePasswordAuthenticationFilter.class)
        .securityContext(configurer -> configurer.requireExplicitSave(false))
        .exceptionHandling(
            exceptionHandling ->
                exceptionHandling.authenticationEntryPoint(jwtAuthenticationEntryPoint))
        .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
        .build();
  }

  @Bean
  public CorsConfigurationSource corsConfiguration() {

    CorsConfiguration configuration = new CorsConfiguration();
    String[] split = springConfigProperties.getSecurity().getCors().split(",");
    configuration.setAllowedOrigins(List.of(split));
    configuration.setAllowCredentials(true);
    configuration.setAllowedMethods(
        Arrays.asList("GET", "POST", "OPTIONS", "PUT", "PATCH", "DELETE", "HEAD"));
    configuration.setAllowedHeaders(
        Arrays.asList(
            "Origin",
            "Content-Type",
            "Accept",
            "Access-Control-Allow-Headers",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "X-Requested-With",
            "Authorization"));
    configuration.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);

    return source;
  }

  @Bean
  public FilterRegistrationBean<CorsFilter> corsFilter(CorsConfigurationSource corsConfiguration) {
    FilterRegistrationBean<CorsFilter> bean =
        new FilterRegistrationBean<>(new CorsFilter(corsConfiguration));
    bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
    return bean;
  }
}
