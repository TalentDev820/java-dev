package com.r.crypto.encryption.hibernate.test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.persistence.AttributeConverter;

import static com.r.crypto.util.ExceptionWrapper.wrap;

public class JsonNodeToBytesConverter implements AttributeConverter<JsonNode, byte[]> {
    public static final ObjectMapper mapper = new ObjectMapper();

    @Override
    public byte[] convertToDatabaseColumn(JsonNode json) {
        return json == null ? null : wrap(() -> mapper.writeValueAsBytes(json));
    }

    @Override
    public JsonNode convertToEntityAttribute(byte[] bytes) {
        return bytes == null ? null : wrap(() -> mapper.readValue(bytes, JsonNode.class));
    }
}
