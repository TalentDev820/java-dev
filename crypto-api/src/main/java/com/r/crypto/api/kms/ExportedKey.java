package com.r.crypto.api.kms;

import java.security.Key;

import static com.r.crypto.util.Util.toSimpleString;

public class ExportedKey {
    private final KmsKey kmsKey;
    private final Key key;

    public ExportedKey(KmsKey kmsKey, Key key) {
        this.kmsKey = kmsKey;
        this.key = key;
    }

    public KmsKey getKmsKey() {
        return kmsKey;
    }

    public Key getKey() {
        return key;
    }

    @Override
    public String toString() {
        return "ExportedKey{"
                + "kmsKey=" + kmsKey
                + ", key=" + toSimpleString(key)
                + "}";
    }
}
