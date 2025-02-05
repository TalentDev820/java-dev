package com.r.crypto.encryption.hibernate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

import static com.r.crypto.util.LogUtil.trace;
import static com.r.crypto.util.Util.toSimpleString;

public class SerializedEncryptedObject extends EncryptedObject<Object> implements Serializable {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private static final long serialVersionUID = -1L;

    public static void copy(EncryptedObject<Object> src, EncryptedObject<Object> dst) {
        if (!src.getEntityField().equals(dst.getEntityField())) {
            throw new IllegalStateException("source and destination do not match");
        }

        dst.setCryptotext(src.getCryptotext());
        dst.setTenant(src.getTenant());
        dst.setSaveMode(src.getSaveMode());
        dst.setLifecycle(src.getLifecycle());

        EncryptedTypeModel model = src.getTypeModel();
        if (model.isImmutable()) {
            dst.setPlaintext(src.getPlaintext());
            dst.setEncryptedPlaintext(src.getEncryptedPlaintext());
        } else {
            dst.setPlaintext(model.convertBytesToPlaintext(model.convertPlaintextToBytes(src.getPlaintext())));
            dst.setEncryptedPlaintext(model.convertBytesToPlaintext(model.convertPlaintextToBytes(src.getEncryptedPlaintext())));
        }
    }

    public SerializedEncryptedObject(EncryptedObject<Object> encryptedObject) {
        super(encryptedObject.getEntityField());

        copy(encryptedObject, this);

        trace(logger, () -> "serialized " + toSimpleString(encryptedObject) + " into " + toSimpleString(this));
    }

    public EncryptedObject<Object> deserialize() {
        EncryptedObject<Object> encryptedObject = getTypeModel().createEncryptedObject();

        copy(this, encryptedObject);

        trace(logger, () -> "deserialized " + toSimpleString(this) + " into " + toSimpleString(encryptedObject));
        return encryptedObject;
    }
}
