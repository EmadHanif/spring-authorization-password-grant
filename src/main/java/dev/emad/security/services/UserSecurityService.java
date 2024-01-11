package dev.emad.security.services;

import dev.emad.entities.User;
import dev.emad.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * @author EmadHanif
 */
@Service
public class UserSecurityService implements UserDetailsService {

  @Autowired private UserRepository userRepository;

  @Override
  @Transactional(readOnly = true)
  public User loadUserByUsername(String email) throws UsernameNotFoundException {
    return findByEmailOrUsername(email);
  }

  @Transactional(readOnly = true)
  protected User findByEmailOrUsername(String email) {
    return userRepository
        .findByEmail(email)
        .orElseThrow(
            () -> new UsernameNotFoundException(String.format("%s - not found",email)));
  }
}
