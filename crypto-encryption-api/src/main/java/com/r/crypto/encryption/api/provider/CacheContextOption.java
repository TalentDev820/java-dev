package com.r.crypto.encryption.api.provider;

import com.r.crypto.api.option.CryptoOption;

import java.util.Objects;

import static java.util.Objects.requireNonNull;

public class CacheContextOption extends CryptoOption {
    private final String entityField;
    private final int entitySystemHashCode;
    private final Long entityId;

    public CacheContextOption(String entityField, int entitySystemHashCode, Long entityId) {
        this.entityField = requireNonNull(entityField);
        this.entitySystemHashCode = entitySystemHashCode;
        this.entityId = entityId;
    }

    public int getEntitySystemHashCode() {
        return entitySystemHashCode;
    }

    public Long getEntityId() {
        return entityId;
    }

    public String getEntityField() {
        return entityField;
    }

    public static CacheContextOption findCacheContextOption(CryptoOption... options) {
        return CryptoOption.findOption(CacheContextOption.class, options);
    }

    // CHECKSTYLE:OFF
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CacheContextOption that = (CacheContextOption) o;
        return entitySystemHashCode == that.entitySystemHashCode && entityField.equals(that.entityField) && Objects.equals(entityId, that.entityId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(entityField, entitySystemHashCode, entityId);
    }

    @Override
    public String toString() {
        return "CacheContextOption{"
                + "entityField=" + entityField
                + ", hash=" + entitySystemHashCode
                + ", id=" + entityId
                + "}";
    }
}
