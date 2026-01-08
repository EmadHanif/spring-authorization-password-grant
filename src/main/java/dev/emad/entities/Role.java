package dev.emad.entities;

import dev.emad.entities.relationship.UserRole;
import jakarta.persistence.*;
import java.io.Serial;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author EmadHanif
 */
@Getter
@Setter
@NoArgsConstructor
@Entity(name = "Role")
@Table(name = "roles")
public class Role implements Serializable {

  @Serial private static final long serialVersionUID = -5146249894814286445L;

  @Id
  // Replace it with Snowflake-Like implementation
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Setter(AccessLevel.NONE)
  private Long id;

  @Column(nullable = false, unique = true)
  private String name;

  /* Relationship */
  @OneToMany(mappedBy = "role", fetch = FetchType.LAZY)
  private Set<UserRole> userRoleSet = new HashSet<>();

  public Role(String name) {
    this.name = name;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    Role role = (Role) o;
    return Objects.equals(id, role.id);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(id);
  }
}
