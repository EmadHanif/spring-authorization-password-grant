package dev.emad.exceptions;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.net.URI;
import java.time.LocalDateTime;

/**
 * @author EmadHanif
 */
// A sample example of GlobalExceptionHandler
@ControllerAdvice
public class AppExceptionHandler {

  @ExceptionHandler(Exception.class)
  public ProblemDetail handleException(Exception exception, HttpServletRequest request) {
    ProblemDetail problemDetail =
        ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, exception.getMessage());
    // Setting metadata and title
    problemDetail.setTitle("Exception");
    problemDetail.setInstance(URI.create(request.getRequestURI()));
    problemDetail.setProperty("timestamp", LocalDateTime.now());

    return problemDetail;
  }
}
