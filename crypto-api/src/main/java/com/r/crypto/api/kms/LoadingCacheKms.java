package com.r.crypto.api.kms;

import static com.r.crypto.api.kms.KmsKey.VERSION_DELIMITER;
import static com.r.crypto.util.Util.quote;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.api.option.TenantOption;
import com.r.crypto.api.provider.RemoteCryptoProvider;
import com.r.crypto.exception.RCryptoException;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ExecutionException;

public class LoadingCacheKms implements LocalKms {
    public static final int DEFAULT_MAX_SIZE = 50;

    protected final Cache<String, ExportedKey> cache;
    protected final RemoteCryptoProvider provider;

    public LoadingCacheKms(RemoteCryptoProvider provider) {
        this(provider, CacheBuilder.newBuilder().maximumSize(DEFAULT_MAX_SIZE).build());
    }

    public LoadingCacheKms(RemoteCryptoProvider provider, Cache<String, ExportedKey> cache) {
        this.cache = cache;
        this.provider = provider;
    }

    @Override
    public ExportedKey exportKey(KmsKey kmsKey, CryptoOption... options) {
        try {
            return cache.get(createCacheKey(kmsKey, options), () -> provider.exportKey(kmsKey, options));
        } catch (ExecutionException e) {
            throw new RCryptoException(e);
        }
    }

    @Override
    public Integer getActiveVersion(String kmsKeyName, CryptoOption... options) {
        return provider.getActiveVersion(kmsKeyName, options);
    }

    @Override
    public void rotateKey(String kmsKeyName, CryptoOption... options) {
        provider.rotateKey(kmsKeyName, options);
    }

    public Map<String, ExportedKey> exportCache() {
        return Collections.unmodifiableMap(cache.asMap());
    }

    public void clearCache() {
        cache.invalidateAll();
    }

    protected String createCacheKey(KmsKey kmsKey, CryptoOption... options) {
        if (kmsKey == null) {
            return null;
        } else {
            String tenant = TenantOption.findTenant(options);
            return kmsKey.getName()
                    + VERSION_DELIMITER + kmsKey.getVersion()
                    + "@" + quote(tenant);
        }
    }

    @Override
    public String toString() {
        return "LoadingCacheKms{"
                + "provider=" + provider
                + ", cacheKeys=" + cache.asMap().keySet()
                + "}";
    }
}
