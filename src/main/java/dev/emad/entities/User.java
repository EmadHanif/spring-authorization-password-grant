package dev.emad.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import dev.emad.entities.relationship.UserRole;
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
import org.springframework.util.StringUtils;

/**
 * @author EmadHanif
 */
@Table(name = "users")
@Entity(name = "User")
public class User implements UserDetails, Serializable {

  @Serial private static final long serialVersionUID = 3625145227376574078L;

  // Use snowflake-like implementation
  @Getter
  @Setter // Necessary for JwtPreprocessor (based on your requirements)
  @Id
  @Column(updatable = false)
  private Long id;

  @Getter
  @Column(nullable = false, length = 50)
  @NotBlank(message = "Full name is required.")
  @Length(min = 3, max = 20, message = "Full name min. length is 3 and max length is 20.")
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

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    Set<GrantedAuthority> authorities = new HashSet<>();
    userRoleSet.forEach(
        user ->
            authorities.add(new SimpleGrantedAuthority(user.getRole().getName().toUpperCase())));
    return authorities;
  }

  public void setFullName(String fullName) {
    this.fullName = StringUtils.capitalize(fullName).strip();
  }

  public void setEmail(String email) {
    this.email = email.toLowerCase().strip();
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

  // Convenience Methods
  public void addUserRole(Role role) {
    if (Objects.isNull(role)) throw new IllegalArgumentException("Role is null.");
    UserRole userRole = new UserRole(this, role);
    this.userRoleSet.add(userRole);
  }
}
