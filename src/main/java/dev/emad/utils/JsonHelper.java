package dev.emad.utils;

import com.fasterxml.jackson.annotation.JsonInclude;
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

    // Excluding properties with null values when serializing...
    objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
  }

  public static String convertToString(Object object) {
    try {
      return objectMapper.writeValueAsString(object);
    } catch (JsonProcessingException e) {
      throw new RuntimeException("Failed to convert object to JSON: " + e.getMessage());
    }
  }

  public static String convertToStringPretty(Object object) {
    try {
      return objectMapper.writer().withDefaultPrettyPrinter().writeValueAsString(object);
    } catch (JsonProcessingException e) {
      throw new RuntimeException("Failed to convert object to JSON: " + e.getMessage());
    }
  }

  public static <T> T convertToObject(Map<String, Object> body, Class<T> clazz) {
      return objectMapper.convertValue(body, clazz);
  }

  public static <T> T convertToObject(String jsonString, Class<T> clazz) {
    try {
      return objectMapper.readValue(jsonString, clazz);
    } catch (JsonProcessingException e) {
      throw new RuntimeException("Failed to convert Json to object: " + e.getMessage());
    }
  }

  public static boolean isValidJson(String jsonString) {
    try {
      objectMapper.readTree(jsonString);
      return true;
    } catch (JsonProcessingException e) {
      return false;
    }
  }
}
