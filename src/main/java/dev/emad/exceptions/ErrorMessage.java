package dev.emad.exceptions;

import java.time.LocalDateTime;

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
