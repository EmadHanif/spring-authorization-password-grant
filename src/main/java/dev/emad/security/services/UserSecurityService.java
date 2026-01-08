package dev.emad.security.services;

import dev.emad.entities.User;
import dev.emad.repositories.UserRepository;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @author EmadHanif
 */
@Service
public class UserSecurityService implements UserDetailsService {

  private final UserRepository userRepository;

  public UserSecurityService(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @NonNull
  @Override
  public User loadUserByUsername(@NonNull String email) throws UsernameNotFoundException {
    return this.userRepository
        .findByEmail(email)
        .orElseThrow(
            () -> new UsernameNotFoundException("Username not found with email: " + email));
  }
}
