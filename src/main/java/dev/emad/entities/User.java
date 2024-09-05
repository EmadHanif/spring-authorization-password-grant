package dev.emad.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.github.f4b6a3.uuid.UuidCreator;
import dev.emad.entities.relationship.UserRole;
import dev.emad.utils.StringHelper;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import java.io.Serial;
import java.io.Serializable;
import java.util.*;

import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.Length;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * @author EmadHanif
 */
@Table(name = "users")
@Entity(name = "User")
public class User implements UserDetails, Serializable {

  @Serial private static final long serialVersionUID = 3625145227376574078L;

  // This is just for the example.
  // Replace UUID with Long (always prefer Snowflake-like implementation)
  // Always avoid using UUIDs as a primary-key.
  // Good Practice: Create & Use Annotations to implement it...
  @Getter
  @Setter // Necessary for JwtPreprocessor (based on your requirements)
  @Id
  @Column(updatable = false)
  private UUID id;

  @Getter
  @Column(nullable = false, length = 50)
  @NotBlank(message = "Full name is required.")
  @Length(
      min = 3,
      max = 20,
      message = "Full name min. length needs to be 3 & max length needs to be 20.")
  private String fullName;

  @Setter
  @Column(nullable = false)
  private String password;

  @Getter
  @Column(nullable = false, unique = true)
  @NotBlank(message = "Email is required,")
  @Email(message = "Email appears to be invalid.")
  private String email;

  // User Role
  @Getter
  @OneToMany(
      fetch = FetchType.LAZY,
      cascade = CascadeType.ALL,
      orphanRemoval = true,
      mappedBy = "user")
  @JsonIgnore // Added to avoid infinite recursion
  private Set<UserRole> userRoleSet = new HashSet<>();

  @Transient private Collection<? extends GrantedAuthority> authorities;

  public void addUserRole(Role role) {

    if (Objects.isNull(role)) throw new IllegalArgumentException("Role cannot be null.");

    // Case: When updating the user roles
    if (Objects.isNull(this.id)) {
      this.id = UuidCreator.getRandomBased();
    }
    UserRole userRole = new UserRole(this, role);
    this.userRoleSet.add(userRole);
  }

  @PrePersist
  public void prePersist() {
    if (Objects.isNull(this.id)) {
      this.id = UuidCreator.getRandomBased();
    }
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    Set<GrantedAuthority> authorities = new HashSet<>();
    userRoleSet.forEach(
        user ->
            authorities.add(new SimpleGrantedAuthority(user.getRole().getName().toUpperCase())));
    return authorities;
  }

  public void setFullName(String fullName) {
    this.fullName = StringHelper.changeFirstCharacterCase(fullName, true);
  }

  public void setEmail(String email) {
    this.email = StringHelper.changeFirstCharacterCase(email, false);
  }

  public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
    this.authorities = authorities;
  }

  @Override
  public String getPassword() {
    return password;
  }

  // Must be added to db fields (a good prc is to use one-to-one table)
  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }

  @Override
  public String getUsername() {
    return email;
  }

  @Override
  public boolean equals(Object object) {
    if (this == object) return true;
    if (object == null || getClass() != object.getClass()) return false;

    User user = (User) object;

    return id.equals(user.id);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(id);
  }
}
