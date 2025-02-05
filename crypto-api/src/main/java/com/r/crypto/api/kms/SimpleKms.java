package com.r.crypto.api.kms;

import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.api.option.KeySupplierOption;
import com.r.crypto.exception.RCryptoMissingKeyException;

import java.security.Key;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static com.r.crypto.api.option.TenantOption.findTenant;
import static com.r.crypto.util.Util.quote;
import static com.r.crypto.util.Util.toSimpleString;
import static java.util.Objects.requireNonNull;

public class SimpleKms implements LocalKms {
    private final Map<String, List<Key>> keys = new HashMap<>();

    public void addKey(String kmsKeyName, Key key) {
        addKey(kmsKeyName, key, (CryptoOption) null);
    }

    public void addKey(String kmsKeyName, Key key, CryptoOption... options) {
        String cacheKey = createCacheKey(kmsKeyName, options);
        keys.computeIfAbsent(cacheKey, k -> new ArrayList<>()).add(key);
    }

    public void removeKey(String kmsKeyName, CryptoOption... options) {
        String cacheKey = createCacheKey(kmsKeyName, options);
        keys.remove(cacheKey);
    }

    @Override
    public ExportedKey exportKey(KmsKey kmsKey, CryptoOption... options) {
        List<Key> versions = findKey(kmsKey, options);
        int version = kmsKey.getVersion() == null ? versions.size() : kmsKey.getVersion();
        return new ExportedKey(new KmsKey(kmsKey.getName(), version), versions.get(version - 1));
    }

    @Override
    public Integer getActiveVersion(String kmsKeyName, CryptoOption... options) {
        List<Key> versions = findKey(kmsKeyName, options);
        return versions.size();
    }

    @Override
    public void rotateKey(String kmsKeyName, CryptoOption... options) {
        List<Key> versions = findKey(kmsKeyName, options);
        Supplier<Key> keySupplier = requireNonNull(KeySupplierOption.findKeySupplier(options));
        versions.add(keySupplier.get());
    }

    protected List<Key> findKey(KmsKey kmsKey, CryptoOption[] options) {
        requireNonNull(kmsKey, "kmsKey is null");
        return findKey(kmsKey.getName(), options);
    }

    protected List<Key> findKey(String kmsKeyName, CryptoOption[] options) {
        requireNonNull(kmsKeyName, "kmsKeyName is null");
        String cacheKey = createCacheKey(kmsKeyName, options);
        List<Key> versions = keys.get(cacheKey);
        if (versions == null) {
            throw new RCryptoMissingKeyException(
                    "kmsKeyName=" + quote(kmsKeyName) + " not found, tenant=" + quote(findTenant(options))
            );
        }
        return versions;
    }

    protected String createCacheKey(String kmsKeyName, CryptoOption... options) {
        if (kmsKeyName == null) {
            throw new IllegalStateException("kmsKeyName is null");
        }
        return kmsKeyName + "@" + quote(findTenant(options));
    }

    @Override
    public String toString() {
        return toSimpleString(this) + "{" + "keys=" + keys.keySet() + "}";
    }
}
