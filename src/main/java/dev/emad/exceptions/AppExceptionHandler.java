package dev.emad.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.LocalDateTime;

/**
 * @author EmadHanif
 */
// A sample example of GlobalExceptionHandler
@ControllerAdvice
public class AppExceptionHandler {

  @ExceptionHandler(Exception.class)
  public ProblemDetail handleException(Exception exception) {
    ProblemDetail problemDetail =
        ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, exception.getMessage());
    // Setting metadata and title
    problemDetail.setTitle("Exception");
    problemDetail.setProperty("timestamp", LocalDateTime.now());

    return problemDetail;
  }
}
