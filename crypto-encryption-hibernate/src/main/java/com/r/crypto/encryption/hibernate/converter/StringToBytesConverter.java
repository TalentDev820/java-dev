package com.r.crypto.encryption.hibernate.converter;

import javax.persistence.AttributeConverter;

import static java.nio.charset.StandardCharsets.UTF_8;

public class StringToBytesConverter implements AttributeConverter<String, byte[]> {
    @Override
    public byte[] convertToDatabaseColumn(String attribute) {
        return attribute == null ? null : attribute.getBytes(UTF_8);
    }

    @Override
    public String convertToEntityAttribute(byte[] bytes) {
        return bytes == null ? null : new String(bytes, UTF_8);
    }
}
