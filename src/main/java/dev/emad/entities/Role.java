package dev.emad.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import java.io.Serial;
import java.io.Serializable;
import java.util.HashSet;
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
@JsonIgnoreProperties(value = {"id"})
public class Role implements Serializable {

  @Serial @Transient private static final long serialVersionUID = -5146249894814286445L;

  @Id
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
}
