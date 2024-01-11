package dev.emad.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;

import java.text.SimpleDateFormat;
import java.util.Map;

/**
 * @author EmadHanif
 */
public class JsonHelper {

  private static final ObjectMapper objectMapper;

  static {
    objectMapper = new ObjectMapper();
    objectMapper.registerModule(new JavaTimeModule());
    objectMapper.registerModule(new ParameterNamesModule());
    objectMapper.registerModule(new Jdk8Module());
    objectMapper.setDateFormat(new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss"));
    objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
  }

  public static String convertToString(Object object) {
    try {
      ObjectWriter ow = objectMapper.writer().withDefaultPrettyPrinter();
      return ow.writeValueAsString(object);
    } catch (JsonProcessingException e) {
      throw new RuntimeException("Failed to convert object to Json: " + e.getMessage());
    }
  }

  public static <T> T convertToObject(Map<String, Object> body, Class<T> clazz) {
    try {
      return objectMapper.readValue(objectMapper.writeValueAsString(body), clazz);
    } catch (JsonProcessingException e) {
      throw new RuntimeException("Failed to convert Map to object: " + e.getMessage());
    }
  }

  public static <T> T convertToObject(String jsonString, Class<T> clazz) {
    try {
      return objectMapper.readValue(jsonString, clazz);
    } catch (JsonProcessingException e) {
      throw new RuntimeException("Failed to convert Json to object: " + e.getMessage());
    }
  }

  public static String prettyPrint(String jsonString) {
    try {
      JsonNode jsonNode = objectMapper.readTree(jsonString);
      return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonNode);
    } catch (JsonProcessingException e) {
      throw new RuntimeException(
          "Failed to convert object to pretty-printed Json: " + e.getMessage());
    }
  }
}
