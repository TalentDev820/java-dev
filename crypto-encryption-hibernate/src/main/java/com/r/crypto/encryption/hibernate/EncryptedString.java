package com.r.crypto.encryption.hibernate;

public class EncryptedString extends EncryptedObject<String> {
    public EncryptedString(String entityField) {
        super(entityField);
    }

    public EncryptedString(Object parentEntity, String fieldName) {
        super(parentEntity, fieldName);
    }

    public EncryptedString(Object parentEntity, String fieldName, String plaintext) {
        super(parentEntity, fieldName, plaintext);
    }
}
