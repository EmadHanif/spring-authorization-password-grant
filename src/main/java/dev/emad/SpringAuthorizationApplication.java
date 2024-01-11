package dev.emad;

import com.github.f4b6a3.uuid.UuidCreator;
import dev.emad.configuration.SpringConfigProperties;
import dev.emad.entities.Role;
import dev.emad.entities.User;
import dev.emad.entities.UserRole;
import dev.emad.repositories.RoleRepository;
import dev.emad.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/*
 @author EmadHanif
*/
@SpringBootApplication
public class SpringAuthorizationApplication implements CommandLineRunner {

  private final RoleRepository roleRepository;
  private final PasswordEncoder passwordEncoder;
  private final UserRepository userRepository;
  private final SpringConfigProperties springConfigProperties;
  private final TokenSettings tokenSettings;
  private final ClientSettings clientSettings;
  private final RegisteredClientRepository registeredClientRepository;

  public SpringAuthorizationApplication(
      RoleRepository roleRepository,
      PasswordEncoder passwordEncoder,
      UserRepository userRepository,
      SpringConfigProperties springConfigProperties,
      TokenSettings tokenSettings,
      ClientSettings clientSettings,
      RegisteredClientRepository registeredClientRepository) {
    this.roleRepository = roleRepository;
    this.passwordEncoder = passwordEncoder;
    this.userRepository = userRepository;
    this.springConfigProperties = springConfigProperties;
    this.tokenSettings = tokenSettings;
    this.clientSettings = clientSettings;
    this.registeredClientRepository = registeredClientRepository;
  }

  public static void main(String[] args) {
    new SpringApplicationBuilder(SpringAuthorizationApplication.class).run(args);
  }

  @Override
  public void run(String... args) {

    /* This is a classical implementation to create user & store it in db; */
    Role role = new Role();
    role.setName("ROLE_ADMIN");

    role = roleRepository.save(role);

    User user = new User();
    user.setEmail("david_freed@gmail.com");
    user.setFullName("David Freed");
    user.setPassword(passwordEncoder.encode("adminadmin"));
    user.addUserRole(new UserRole(role));

    // User created & storing in db.
    userRepository.save(user);

    // This is a classical example to create RegisteredClient...
    Set<String> redirectUrisSet =
        new HashSet<>(
            Arrays.asList(springConfigProperties.getSecurity().getRedirectUris().split(",")));

    RegisteredClient registeredClient =
        RegisteredClient.withId(UuidCreator.getRandomBased().toString())
            .clientId("spring-angular")
            .clientSecret(passwordEncoder.encode("spring-angular-client-key"))
            .scope("read")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope("message.read")
            .scope("message.write")
            .scope("write")
            .redirectUris(uris -> uris.addAll(redirectUrisSet))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.PASSWORD)
            .tokenSettings(tokenSettings)
            .clientSettings(clientSettings)
            .build();

    registeredClientRepository.save(registeredClient);
  }
}
