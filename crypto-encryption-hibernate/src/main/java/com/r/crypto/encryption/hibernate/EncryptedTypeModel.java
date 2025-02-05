package com.r.crypto.encryption.hibernate;

import com.r.crypto.encryption.exception.RCryptoEncryptionException;
import org.hibernate.type.descriptor.jdbc.JdbcType;

import jakarta.persistence.AttributeConverter;
import java.lang.reflect.Field;

import static com.r.crypto.util.ExceptionWrapper.wrap;
import static com.r.crypto.util.Util.cast;
import static com.r.crypto.util.Util.quote;
import static com.r.crypto.util.Util.toSimpleString;

public class EncryptedTypeModel {
    protected final String entityField;
    protected final Class<?> entityClass;
    protected final String fieldName;
    protected EncryptedEntityModel entityModel;
    protected Class<EncryptedObject<Object>> encryptedObjectClass;
    protected String virtualKey;
    protected boolean mutable;

    protected String plaintextColumnName;
    protected JdbcType plaintextColumnType;
    protected int plaintextColumnIndex;

    protected String ciphertextColumnName;
    protected JdbcType ciphertextColumnType;
    protected int ciphertextColumnIndex;

    protected String ciphertextHeaderColumnName;
    protected JdbcType ciphertextHeaderColumnType;
    protected int ciphertextHeaderColumnIndex;

    protected AttributeConverter<Object, byte[]> bytesConverter;
    protected AttributeConverter<Object, Object> columnConverter;

    public EncryptedTypeModel(String entityField) {
        try {
            this.entityField = entityField;
            this.entityClass = Class.forName(entityField.substring(0, entityField.lastIndexOf('.')));
            this.fieldName = entityField.substring(entityField.lastIndexOf('.') + 1);
        } catch (ClassNotFoundException e) {
            throw new RCryptoEncryptionException(e);
        }
    }

    public Class<?> getEntityClass() {
        return entityClass;
    }

    public String getFieldName() {
        return fieldName;
    }

    public String getSimpleFieldName() {
        return entityClass.getSimpleName() + "." + fieldName;
    }

    public String getEntityField() {
        return entityField;
    }

    public EncryptedEntityModel getEntityModel() {
        return entityModel;
    }

    public void setEntityModel(EncryptedEntityModel entityModel) {
        this.entityModel = entityModel;
    }

    public Class<EncryptedObject<Object>> getEncryptedObjectClass() {
        return encryptedObjectClass;
    }

    public void setEncryptedObjectClass(String encryptedObjectClass) {
        this.encryptedObjectClass = wrap(() -> cast(Class.forName(encryptedObjectClass)));
    }

    public EncryptedObject<Object> createEncryptedObject() {
        return wrap(() -> encryptedObjectClass.getConstructor(String.class).newInstance(entityField));
    }

    public String getVirtualKey() {
        return virtualKey;
    }

    public void setVirtualKey(String virtualKey) {
        this.virtualKey = virtualKey;
    }

    public boolean isMutable() {
        return mutable;
    }

    public boolean isImmutable() {
        return !mutable;
    }

    public void setMutable(boolean mutable) {
        this.mutable = mutable;
    }

    public String getPlaintextColumnName() {
        return plaintextColumnName;
    }

    public void setPlaintextColumnName(String plaintextColumnName) {
        this.plaintextColumnName = plaintextColumnName;
    }

    public JdbcType getPlaintextColumnType() {
        return plaintextColumnType;
    }

    public void setPlaintextColumnType(JdbcType plaintextColumnType) {
        this.plaintextColumnType = plaintextColumnType;
    }

    public int getPlaintextColumnIndex() {
        return plaintextColumnIndex;
    }

    public void setPlaintextColumnIndex(int plaintextColumnIndex) {
        this.plaintextColumnIndex = plaintextColumnIndex;
    }

    public String getCiphertextColumnName() {
        return ciphertextColumnName;
    }

    public void setCiphertextColumnName(String ciphertextColumnName) {
        this.ciphertextColumnName = ciphertextColumnName;
    }

    public JdbcType getCiphertextColumnType() {
        return ciphertextColumnType;
    }

    public void setCiphertextColumnType(JdbcType ciphertextColumnType) {
        this.ciphertextColumnType = ciphertextColumnType;
    }

    public int getCiphertextColumnIndex() {
        return ciphertextColumnIndex;
    }

    public void setCiphertextColumnIndex(int ciphertextColumnIndex) {
        this.ciphertextColumnIndex = ciphertextColumnIndex;
    }

    public String getCiphertextHeaderColumnName() {
        return ciphertextHeaderColumnName;
    }

    public void setCiphertextHeaderColumnName(String ciphertextHeaderColumnName) {
        this.ciphertextHeaderColumnName = ciphertextHeaderColumnName;
    }

    public JdbcType getCiphertextHeaderColumnType() {
        return ciphertextHeaderColumnType;
    }

    public void setCiphertextHeaderColumnType(JdbcType ciphertextHeaderColumnType) {
        this.ciphertextHeaderColumnType = ciphertextHeaderColumnType;
    }

    public int getCiphertextHeaderColumnIndex() {
        return ciphertextHeaderColumnIndex;
    }

    public void setCiphertextHeaderColumnIndex(int ciphertextHeaderColumnIndex) {
        this.ciphertextHeaderColumnIndex = ciphertextHeaderColumnIndex;
    }

    public AttributeConverter<Object, byte[]> getBytesConverter() {
        return bytesConverter;
    }

    @SuppressWarnings("unchecked")
    public void setBytesConverter(AttributeConverter<?, byte[]> bytesConverter) {
        this.bytesConverter = (AttributeConverter<Object, byte[]>) bytesConverter;
    }

    public Object convertBytesToPlaintext(byte[] bytes) {
        return bytesConverter.convertToEntityAttribute(bytes);
    }

    public byte[] convertPlaintextToBytes(Object plaintext) {
        return bytesConverter.convertToDatabaseColumn(plaintext);
    }

    public AttributeConverter<Object, Object> getColumnConverter() {
        return columnConverter;
    }

    @SuppressWarnings("unchecked")
    public void setColumnConverter(AttributeConverter<?, ?> columnConverter) {
        this.columnConverter = (AttributeConverter<Object, Object>) columnConverter;
    }

    public Object convertColumnToPlaintext(Object columnValue) {
        return columnConverter.convertToEntityAttribute(columnValue);
    }

    public Object convertPlaintextToColumn(Object plaintext) {
        return columnConverter.convertToDatabaseColumn(plaintext);
    }

    public byte[] convertColumnToBytes(Object columnValue) {
        return convertPlaintextToBytes(convertColumnToPlaintext(columnValue));
    }

    public Object convertBytesToColumn(byte[] bytes) {
        return convertPlaintextToColumn(convertBytesToPlaintext(bytes));
    }

    public EncryptedObject<Object> getEncryptedObject(Object entity) {
        try {
            Field javaField = entity.getClass().getDeclaredField(entityField.substring(entityField.lastIndexOf('.') + 1));
            if (!javaField.canAccess(entity)) {
                javaField.setAccessible(true);
            }
            return cast(javaField.get(entity));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean hasPlaintextColumn() {
        return plaintextColumnName != null;
    }

    public boolean hasCiphertextColumn() {
        return ciphertextColumnName != null;
    }

    public boolean hasCiphertextHeaderColumn() {
        return ciphertextHeaderColumnName != null;
    }

    @Override
    public String toString() {
        return toSimpleString(this) + "{"
                + "field=" + entityClass.getSimpleName() + "." + fieldName
                + ", virtualKey=" + quote(virtualKey)
                + ", mutable=" + mutable

                + ", plaintext=["
                + plaintextColumnIndex
                + "," + (plaintextColumnType == null ? null : plaintextColumnType.getClass().getName())
                + "," + quote(plaintextColumnName)
                + "]"

                + ", ciphertext=["
                + ciphertextColumnIndex
                + "," + (ciphertextColumnType == null ? null : ciphertextColumnType.getClass().getName())
                + "," + quote(ciphertextColumnName)
                + "]"

                + ", header=["
                + ciphertextHeaderColumnIndex
                + "," + (ciphertextHeaderColumnType == null ? null : ciphertextHeaderColumnType.getClass().getName())
                + "," + quote(ciphertextHeaderColumnName)
                + "]"

                + ", plaintextToBytesConverter="
                + (bytesConverter == null ? null : bytesConverter.getClass().getSimpleName())
                + ", plaintextToColumnConverter="
                + (columnConverter == null ? null : columnConverter.getClass().getSimpleName())
                + "}";
    }
}
