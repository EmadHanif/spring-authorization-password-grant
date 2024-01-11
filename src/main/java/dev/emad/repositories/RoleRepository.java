package dev.emad.repositories;

import dev.emad.entities.Role;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author EmadHanif
 */
public interface RoleRepository extends JpaRepository<Role, Long> {}
