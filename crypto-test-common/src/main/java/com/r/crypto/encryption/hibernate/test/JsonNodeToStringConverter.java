package com.r.crypto.encryption.hibernate.test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.persistence.AttributeConverter;
import java.io.IOException;

public class JsonNodeToStringConverter implements AttributeConverter<JsonNode, String> {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String convertToDatabaseColumn(JsonNode jsonNode) {
        try {
            return jsonNode == null ? null : objectMapper.writeValueAsString(jsonNode);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public JsonNode convertToEntityAttribute(String s) {
        try {
            return s == null ? null : objectMapper.readValue(s, JsonNode.class);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
