package dev.emad.exceptions;

import java.time.LocalDateTime;
import lombok.*;

/**
 * @author EmadHanif
 */
// Good Practice - Create a centralized exception handler & utilize this class
public class ErrorMessage {
  public String message;
  private LocalDateTime dateTime;

  public ErrorMessage(String message, LocalDateTime dateTime) {
    this.message = message;
    this.dateTime = dateTime;
  }
}
