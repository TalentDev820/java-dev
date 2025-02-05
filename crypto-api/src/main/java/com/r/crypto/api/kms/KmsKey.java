package com.r.crypto.api.kms;

import com.r.crypto.api.Cryptotext;

import java.util.Objects;

/**
 * Represents a cryptographic key stored in a KMS
 */
public class KmsKey {
    public static final String VERSION_DELIMITER = "#";

    private final String name;
    private final Integer version;

    public KmsKey(String name) {
        this(name, null);
    }

    public KmsKey(String name, Integer version) {
        this.name = Objects.requireNonNull(name);
        this.version = version;
    }

    public String getName() {
        return name;
    }

    public Integer getVersion() {
        return version;
    }

    @Override
    public String toString() {
        return version == null ? name : name + VERSION_DELIMITER + version;
    }

    public static KmsKey parse(String s) {
        if (s == null || s.isEmpty()) {
            return null;
        }

        int index = s.indexOf(VERSION_DELIMITER);
        if (index == -1) {
            return new KmsKey(s);
        } else {
            return new KmsKey(s.substring(0, index), Integer.parseInt(s.substring(index + 1)));
        }
    }

    public static KmsKey resolveKey(Cryptotext cryptotext, KmsKey key) {
        if (cryptotext == null) {
            return key;
        }

        KmsKey cryptotextKey = cryptotext.getKey();
        if (cryptotextKey == null && key == null) {
            return null;
        } else if (cryptotextKey != null && key == null) {
            return cryptotextKey;
        } else if (cryptotextKey == null) {
            return key;
        } else if (cryptotextKey.equals(key)) {
            return key;
        } else {
            throw new IllegalStateException("cryptotext key=" + cryptotextKey + " does not match " + key);
        }
    }

    //CHECKSTYLE:OFF because this method is auto-generated
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KmsKey kmsKey = (KmsKey) o;
        return name.equals(kmsKey.name) &&
                Objects.equals(version, kmsKey.version);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, version);
    }
}
