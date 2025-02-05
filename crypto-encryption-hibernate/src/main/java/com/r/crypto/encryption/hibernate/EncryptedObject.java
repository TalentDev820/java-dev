package com.r.crypto.encryption.hibernate;

import com.r.crypto.api.Cryptotext;
import com.r.crypto.encryption.migration.MigrationMode;

import java.util.Objects;

import static com.r.crypto.encryption.hibernate.EncryptedObject.Lifecycle.NEW;
import static com.r.crypto.encryption.hibernate.EncryptedObject.Lifecycle.UPDATED;
import static com.r.crypto.util.Util.mask;
import static com.r.crypto.util.Util.toSimpleString;
import static java.util.Objects.requireNonNull;

public class EncryptedObject<T> {
    /**
     * Enum for the lifecycle of an Encrypted object. These aren't
     * necessarily in order, and this is only used for debugging.
     */
    enum Lifecycle {
        NEW,                // Constructed
        READ,               // Fresh DB read (EncryptedType.nullSafeGet)
        UPDATED,            // Method updatePlaintext called
        WRITTEN,            // Written to DB (EncryptedType.nullSafeSet)
        ENTITY_ENCRYPTED,   // Parent entity processed by EntityEncryptionService.encrypt
        ENTITY_DECRYPTED    // Parent entity processed by EntityEncryptionService.decrypt
    }

    protected T plaintext;
    protected T encryptedPlaintext;
    protected Cryptotext cryptotext;
    protected String tenant;
    protected MigrationMode saveMode;
    protected Lifecycle lifecycle = NEW;
    protected EncryptedTypeModel typeModel;
    protected final String entityField;

    public EncryptedObject(String entityField) {
        requireNonNull(entityField);
        if (entityField.indexOf('.') == -1) {
            throw new IllegalArgumentException("entityField must be prefixed by parent entity class name");
        }
        this.entityField = entityField;
    }

    public EncryptedObject(Object parentEntity, String fieldName) {
        this(parentEntity.getClass(), fieldName);
    }

    public EncryptedObject(Object parentEntity, String fieldName, T plaintext) {
        this(parentEntity.getClass(), fieldName);
        setPlaintext(plaintext);
    }

    public EncryptedObject(Class<?> parentEntityClass, String fieldName) {
        if (fieldName.indexOf('.') != -1) {
            throw new IllegalArgumentException("fieldName=" + fieldName + " cannot contain periods");
        }
        this.entityField = parentEntityClass.getName() + "." + fieldName;
    }

    public EncryptedObject(
            T plaintext,
            Cryptotext cryptotext,
            String tenant,
            String entityField
    ) {
        this.plaintext = plaintext;
        this.cryptotext = cryptotext;
        this.tenant = tenant;
        this.entityField = requireNonNull(entityField);
    }

    public EncryptedObject(EncryptedObject<T> encryptedObject) {
        this.plaintext = encryptedObject.getPlaintext();
        this.encryptedPlaintext = encryptedObject.getEncryptedPlaintext();
        this.cryptotext = encryptedObject.getCryptotext();
        this.tenant = encryptedObject.getTenant();
        this.entityField = encryptedObject.getEntityField();
        this.typeModel = encryptedObject.getTypeModel();
        this.saveMode = encryptedObject.getSaveMode();
        this.lifecycle = encryptedObject.getLifecycle();
    }

    public T getPlaintext() {
        return plaintext;
    }

    public void updatePlaintext(T plaintext) {
        // Avoid unnecessary write to the database since listener will re-encrypt otherwise
        if (!Objects.equals(this.plaintext, plaintext)) {
            this.plaintext = plaintext;
            this.encryptedPlaintext = null;
            this.cryptotext = null;
            this.saveMode = null;
            this.lifecycle = UPDATED;
        }
    }

    public String getEntityField() {
        return entityField;
    }

    public EncryptedTypeModel getTypeModel() {
        if (typeModel == null) {
            typeModel = requireNonNull(EncryptedType.getTypeModel(entityField));
        }
        return typeModel;
    }

    public byte[] getCiphertext() {
        return cryptotext == null ? null : cryptotext.getData();
    }

    public String getTenant() {
        return tenant;
    }

    public void setTenant(String tenant) {
        this.tenant = tenant;
    }

    public Cryptotext getCryptotext() {
        return cryptotext;
    }

    public void setCryptotext(Cryptotext cryptotext) {
        this.cryptotext = cryptotext;
    }

    public MigrationMode getSaveMode() {
        return saveMode;
    }

    public void setSaveMode(MigrationMode saveMode) {
        this.saveMode = saveMode;
    }

    protected void setPlaintext(T plaintext) {
        this.plaintext = plaintext;
    }

    public T getEncryptedPlaintext() {
        return encryptedPlaintext;
    }

    public void setEncryptedPlaintext(T encryptedPlaintext) {
        this.encryptedPlaintext = encryptedPlaintext;
    }

    public Lifecycle getLifecycle() {
        return lifecycle;
    }

    public void setLifecycle(Lifecycle lifecycle) {
        this.lifecycle = lifecycle;
    }

    public String dataState() {
        return (plaintext == null ? "X" : "P")
                + (encryptedPlaintext == null ? "X" : "E")
                + (cryptotext == null ? "X" : "C");
    }

    public String state() {
        return "[" + dataState() + "," + lifecycle + "," + saveMode + "]";
    }

    public boolean hasEncryptableContent() {
        return plaintext != null || encryptedPlaintext != null;
    }

    @Override
    public String toString() {
        final String encryptedPlaintextString;
        if (plaintext == null && encryptedPlaintext == null) {
            encryptedPlaintextString = "null";
        } else if (plaintext == encryptedPlaintext) {
            encryptedPlaintextString = "same";
        } else if (Objects.deepEquals(plaintext, encryptedPlaintext)) {
            encryptedPlaintextString = "equals";
        } else {
            encryptedPlaintextString = mask(encryptedPlaintext);
        }

        return toSimpleString(this) + "{"
                + getTypeModel().getSimpleFieldName()
                + " state=" + state()
                + " plaintext=" + mask(plaintext)
                + " encryptedPlaintext=" + encryptedPlaintextString
                + " cryptotext=" + cryptotext
                + " tenant=" + tenant
                + "}";
    }
}
