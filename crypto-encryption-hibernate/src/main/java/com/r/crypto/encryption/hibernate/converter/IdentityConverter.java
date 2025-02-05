package com.r.crypto.encryption.hibernate.converter;

import jakarta.persistence.AttributeConverter;

public class IdentityConverter implements AttributeConverter<Object, Object> {
    @Override
    public Object convertToDatabaseColumn(Object attribute) {
        return attribute;
    }

    @Override
    public Object convertToEntityAttribute(Object dbData) {
        return dbData;
    }
}
