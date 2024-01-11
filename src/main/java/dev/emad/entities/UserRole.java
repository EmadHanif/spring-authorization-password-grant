package dev.emad.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.github.f4b6a3.uuid.UuidCreator;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author EmadHanif
 */
@Getter
@Setter
@NoArgsConstructor
@Entity(name = "UserRole")
@Table(name = "user_roles")
public class UserRole implements Serializable {

  @Serial private static final long serialVersionUID = 5763287331019765195L;

  @Id
  @Column(length = 50, nullable = false, updatable = false)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "user_fk")
  @NotNull(message = "User cannot be null.")
  @JsonIgnore
  private User user;

  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "role_fk")
  @NotNull(message = "Role cannot be null")
  private Role role;

  public UserRole(Role role) {
    this.role = role;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    UserRole userRole = (UserRole) o;

    return Objects.equals(id, userRole.id);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(id);
  }

  @PrePersist
  public void prePersist() {
    this.id = UuidCreator.getRandomBased();
  }
}
