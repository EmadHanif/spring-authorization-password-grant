package dev.emad;

import dev.emad.configuration.SpringConfigProperties;
import dev.emad.entities.Role;
import dev.emad.entities.User;
import dev.emad.repositories.RoleRepository;
import dev.emad.repositories.UserRepository;
import dev.emad.security.config.SecurityManager;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.boot.CommandLineRunner;
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
import org.springframework.transaction.annotation.Transactional;

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

  @PersistenceContext private EntityManager entityManager;

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

    /*
    This is a just an example to create user which is being invoked in CommandLineRunner
    The core purpose of this repository is to implement a template for OAuth2.0 Password Grant Authentication
    Using Spring Authorization Server (replacing spring-security-oauth2.0)
    */

    /*
    Generally, my recommendation is to create your own implementation which entails
    persistOrUpdate(obj), persistOrUpdateInBatch(obj) removeAllInBatch, remove(obj) impl
    via EntityManager
     */
    Role role = new Role();
    role.setName("ROLE_ADMIN");

    // Saving Role...
    role = this.roleRepository.save(role);

    User user = new User();
    user.setEmail("david_freed@gmail.com");
    user.setFullName("David Freed");
    user.setPassword(this.passwordEncoder.encode("adminadmin"));

    // Adding role...
    user.addUserRole(role);

    // User created & storing in db.
    this.userRepository.save(user);

    // This is a classical example to create RegisteredClient...
    Set<String> redirectUrisSet =
        new HashSet<>(
            Arrays.asList(springConfigProperties.getSecurity().getRedirectUris().split(",")));

    RegisteredClient registeredClient =
        RegisteredClient.withId(SecurityManager.REGISTERED_CLIENT_ID)
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
            .tokenSettings(this.tokenSettings)
            .clientSettings(this.clientSettings)
            .build();

    this.registeredClientRepository.save(registeredClient);
  }
}
