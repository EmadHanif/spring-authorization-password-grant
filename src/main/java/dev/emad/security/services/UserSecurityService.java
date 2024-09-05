package dev.emad.security.services;

import dev.emad.entities.User;
import dev.emad.repositories.UserRepository;
import dev.emad.services.UserService;
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

  private final UserService userService;

  public UserSecurityService(UserService userService) {
    this.userService = userService;
  }

  /*
   When you are building an application with multiple clients;
   Here's the basic recipe or layout.
   1. Get the origin via Origin or Referer Header (if it's not null)
   2. If the client-1(which is for customer) is accessing then, verify if the user has ROLE_CUSTOMER; otherwise throw error
   3. If the client-2(which is for admin users) is accessing then, verify if the user has ROLE_ADMIN; otherwise throw error
  */
  @Override
  public User loadUserByUsername(String email) throws UsernameNotFoundException {
    return this.userService.findByEmail(email);
  }
}
