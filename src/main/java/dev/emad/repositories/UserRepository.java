package dev.emad.repositories;

import dev.emad.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.lang.NonNull;

import java.util.Optional;
import java.util.UUID;

/**
 * @author EmadHanif
 */
public interface UserRepository extends JpaRepository<User, UUID> {

  Optional<User> findByEmail(@NonNull String email);
}
