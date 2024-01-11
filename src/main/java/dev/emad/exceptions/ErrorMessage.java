package dev.emad.exceptions;

import java.time.LocalDateTime;
import lombok.*;

/**
 * @author EmadHanif
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class ErrorMessage {
  public String message;
  private LocalDateTime dateTime;
}
