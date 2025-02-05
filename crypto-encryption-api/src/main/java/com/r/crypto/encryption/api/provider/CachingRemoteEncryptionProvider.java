package com.r.crypto.encryption.api.provider;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.r.crypto.api.CryptoAlgorithm;
import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.kms.ExportedKey;
import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.api.option.TenantOption;
import com.r.crypto.encryption.api.EncryptionItem;
import com.r.crypto.encryption.api.EncryptionOperation;
import com.r.crypto.encryption.exception.RCryptoEncryptionException;
import com.r.crypto.util.Timer;
import com.r.crypto.util.Timer.TimedResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static com.r.crypto.api.option.TenantOption.findTenant;
import static com.r.crypto.api.option.TenantOption.resolveTenant;
import static com.r.crypto.encryption.api.EncryptionOperation.DECRYPT;
import static com.r.crypto.encryption.api.EncryptionOperation.ENCRYPT;
import static com.r.crypto.encryption.api.EncryptionOperation.REWRAP;
import static com.r.crypto.encryption.api.provider.CacheContextOption.findCacheContextOption;
import static com.r.crypto.util.Util.quote;
import static com.r.crypto.util.Util.toSimpleString;
import static java.util.Objects.requireNonNull;

/** Experimental, do not use */
class CachingRemoteEncryptionProvider implements RemoteEncryptionProvider {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final Timer timer = new Timer(logger, RCryptoEncryptionException.class);

    protected final RemoteEncryptionProvider provider;
    protected final Cache<CryptotextCacheKey, byte[]> cryptotextCache;
    protected final Cache<PlaintextCacheKey, Cryptotext> plaintextCache;

    public CachingRemoteEncryptionProvider(RemoteEncryptionProvider provider) {
        this(provider, 100);
    }

    public CachingRemoteEncryptionProvider(RemoteEncryptionProvider provider, int size) {
        this(provider,
                CacheBuilder.newBuilder().maximumSize(size).expireAfterAccess(5, TimeUnit.MINUTES).build(),
                CacheBuilder.newBuilder().maximumSize(size).expireAfterAccess(5, TimeUnit.MINUTES).build());
    }

    public CachingRemoteEncryptionProvider(
            RemoteEncryptionProvider provider,
            Cache<CryptotextCacheKey, byte[]> cryptotextCache,
            Cache<PlaintextCacheKey, Cryptotext> plaintextCache
    ) {
        this.provider = requireNonNull(provider);
        this.cryptotextCache = requireNonNull(cryptotextCache);
        this.plaintextCache = requireNonNull(plaintextCache);
    }

    @Override
    public Cryptotext encrypt(byte[] plaintext, CryptoAlgorithm algorithm, KmsKey kmsKey, CryptoOption... options) {
        requireNonNull(kmsKey);
        if (plaintext == null) {
            return null;
        }

        return timer.timedResult("encrypt kmsKey=%s", kmsKey, () -> {
            Cryptotext cryptotext = get(plaintext, kmsKey, options);
            boolean cached = cryptotext != null;
            if (!cached) {
                cryptotext = provider.encrypt(plaintext, algorithm, kmsKey, options);
                cache(ENCRYPT, plaintext, cryptotext, kmsKey, options);
            }
            return new TimedResult<>(cryptotext, "cached=%s", cached);
        });
    }

    @Override
    public byte[] decrypt(Cryptotext cryptotext, KmsKey kmsKey, CryptoOption... options) {
        if (cryptotext == null) {
            return null;
        }

        return timer.timedResult("decrypt kmsKey=%s", kmsKey, () -> {
            CryptoOption[] resolvedOptions = TenantOption.assertTenant(cryptotext, options);
            byte[] plaintext = get(cryptotext, kmsKey, resolvedOptions);
            boolean cached = plaintext != null;
            if (!cached) {
                plaintext = provider.decrypt(cryptotext, kmsKey, resolvedOptions);
                cache(DECRYPT, plaintext, cryptotext, kmsKey, resolvedOptions);
            }
            return new TimedResult<>(plaintext, "cached=%s", cached);
        });
    }

    @Override
    public boolean process(List<EncryptionItem> encryptionItems, boolean batch) {
        return timer.bracketTimedResult("batch items=%d", encryptionItems.size(), () -> {
            List<EncryptionItem> providerItems = new ArrayList<>();
            Map<EncryptionOperation, Map<KmsKey, Map<String, List<EncryptionItem>>>> results = new HashMap<>();
            encryptionItems.forEach(item ->
                    results.computeIfAbsent(item.getOperation(), o -> new HashMap<>())
                            .computeIfAbsent(item.getKmsKey(), k -> new HashMap<>())
                            .computeIfAbsent(findTenant(item.getOptions()), t -> new ArrayList<>()).add(item)
            );

            if (results.containsKey(ENCRYPT)) {
                AtomicInteger total = new AtomicInteger();
                AtomicInteger cached = new AtomicInteger();
                results.get(ENCRYPT).forEach((kmsKey, tenantToItemsMap) ->
                        tenantToItemsMap.forEach((tenant, items) ->
                                items.forEach(item -> {
                                    total.incrementAndGet();
                                    Cryptotext cryptotext = get(item.getPlaintext(), item.getKmsKey(), item.getOptions());
                                    if (cryptotext == null) {
                                        providerItems.add(item);
                                    } else {
                                        cached.incrementAndGet();
                                        item.setCryptotext(cryptotext);
                                        item.setSuccessful();
                                    }
                                })
                        )
                );
                logger.trace("found {}/{} already encrypted", cached, total);
            }

            if (results.containsKey(DECRYPT)) {
                AtomicInteger total = new AtomicInteger();
                AtomicInteger cached = new AtomicInteger();
                results.get(DECRYPT).forEach((kmsKey, tenantToItemsMap) ->
                        tenantToItemsMap.forEach((tenant, items) ->
                                items.forEach(item -> {
                                    total.incrementAndGet();
                                    byte[] plaintext = get(item.getCryptotext(), item.getKmsKey(), item.getOptions());
                                    if (plaintext == null) {
                                        providerItems.add(item);
                                    } else {
                                        cached.incrementAndGet();
                                        item.setPlaintext(plaintext);
                                        item.setSuccessful();
                                    }
                                })
                        )
                );
                logger.trace("found {}/{} already decrypted", cached, total);
            }

            if (results.containsKey(REWRAP)) {
                results.get(REWRAP).forEach((kmsKey, tenantToItemsMap) ->
                        tenantToItemsMap.forEach((tenant, items) -> providerItems.addAll(items))
                );
            }

            boolean batchResult = provider.process(providerItems, true);
            providerItems.forEach(item -> {
                if (item.successful() && (item.getOperation() == ENCRYPT || item.getOperation() == DECRYPT)) {
                    cache(item.getOperation(), item.getPlaintext(), item.getCryptotext(), item.getKmsKey(), item.getOptions());
                }
            });

            return new TimedResult<>(
                    batchResult,
                    "hits=%d misses=%d plaintextCache=%d cryptotextCache=%d",
                    encryptionItems.size() - providerItems.size(),
                    encryptionItems.size(),
                    plaintextCache.size(),
                    cryptotextCache.size()
            );
        });
    }

    private void cache(EncryptionOperation operation, byte[] plaintext, Cryptotext cryptotext, KmsKey requestedKey, CryptoOption... options) {
        int cachedCount = 0;
        String tenant = resolveTenant(cryptotext, options);
        CacheContextOption context = findCacheContextOption(options);
        KmsKey kmsKey = cryptotext.getKey();
        if (kmsKey == null) {
            kmsKey = requestedKey;
        }

        CryptotextCacheKey cryptotextCacheKey = new CryptotextCacheKey(cryptotext, kmsKey, tenant);
        cryptotextCache.put(cryptotextCacheKey, plaintext);
        cachedCount++;
        logger.trace("cached {} to {}", cryptotextCacheKey, new String(plaintext));
        if (context != null) {
            PlaintextCacheKey plaintextCacheKey = new PlaintextCacheKey(plaintext, kmsKey, tenant, context);
            plaintextCache.put(plaintextCacheKey, cryptotext);
            cachedCount++;
            logger.trace("cached {} to {}", plaintextCacheKey, cryptotext);
        }

        KmsKey unversionedKey = new KmsKey(kmsKey.getName());
        if (kmsKey.getVersion() != null && context != null) {
            PlaintextCacheKey plaintextCacheKey = new PlaintextCacheKey(plaintext, unversionedKey, tenant, context);
            plaintextCache.put(plaintextCacheKey, cryptotext);
            cachedCount++;
            logger.trace("cached {} to {}", plaintextCacheKey, cryptotext);
        }

        logger.trace("cached operation={} count={} plaintext=\"{}\" cryptotext={} requestedKey={} kmsKey={} unversionedKey={} tenant={} context={}",
                operation,
                cachedCount,
                new String(plaintext),
                cryptotext.header(),
                requestedKey,
                kmsKey,
                unversionedKey,
                findTenant(options),
                context);
    }

    private Cryptotext get(byte[] plaintext, KmsKey requestedKey, CryptoOption... options) {
        String tenant = findTenant(options);
        CacheContextOption context = findCacheContextOption(options);
        PlaintextCacheKey cacheKey = new PlaintextCacheKey(plaintext, requestedKey, tenant, context);
        Cryptotext cryptotext = plaintextCache.getIfPresent(cacheKey);
        if (cryptotext != null) {
            logger.trace("cache found {} cryptotext={}", cacheKey, cryptotext);
            return cryptotext;
        }

        if (requestedKey.getVersion() != null) {
            KmsKey unversionedKey = new KmsKey(requestedKey.getName());
            PlaintextCacheKey unversionedCacheKey = new PlaintextCacheKey(plaintext, unversionedKey, tenant, context);
            cryptotext = plaintextCache.getIfPresent(unversionedCacheKey);
            if (cryptotext != null) {
                logger.trace("cache found {} cryptotext={}", unversionedCacheKey, cryptotext);
                return cryptotext;
            }
        }

        logger.trace("cache miss encrypt " + cacheKey);
        return null;
    }

    private byte[] get(Cryptotext cryptotext, KmsKey requestedKey, CryptoOption... options) {
        String tenant = resolveTenant(cryptotext, options);
        KmsKey kmsKey = cryptotext.getKey();
        if (kmsKey == null) {
            kmsKey = requestedKey;
        }

        CryptotextCacheKey cacheKey = new CryptotextCacheKey(cryptotext, kmsKey, tenant);
        byte[] plaintext = cryptotextCache.getIfPresent(cacheKey);
        if (plaintext != null) {
            logger.trace("cache found {} plaintext=\"{}\"", cacheKey, new String(plaintext));
            return plaintext;
        }

        if (kmsKey.getVersion() != null) {
            KmsKey unversionedKey = new KmsKey(kmsKey.getName());
            CryptotextCacheKey unversionedCacheKey = new CryptotextCacheKey(cryptotext, unversionedKey, tenant);
            plaintext = cryptotextCache.getIfPresent(unversionedCacheKey);
            if (plaintext != null) {
                logger.trace("cache found {} plaintext=\"{}\"", unversionedCacheKey, new String(plaintext));
                return plaintext;
            }
        }

        logger.trace("cache miss decrypt {}", cacheKey);
        return null;
    }

    @Override
    public Integer getActiveVersion(String kmsKeyName, CryptoOption... options) {
        return provider.getActiveVersion(kmsKeyName, options);
    }

    @Override
    public ExportedKey exportKey(KmsKey kmsKey, CryptoOption... options) {
        return provider.exportKey(kmsKey, options);
    }

    @Override
    public void rotateKey(String kmsKeyName, CryptoOption... options) {
        provider.rotateKey(kmsKeyName, options);
    }

    protected static class CryptotextCacheKey {
        protected final Cryptotext cryptotext;

        public CryptotextCacheKey(Cryptotext cryptotext, KmsKey kmsKey, String tenant) {
            this.cryptotext = Cryptotext.copy(cryptotext);
            this.cryptotext.setKey(kmsKey);
            this.cryptotext.setTenant(tenant);
        }

        // CHECKSTYLE:OFF
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            CryptotextCacheKey that = (CryptotextCacheKey) o;
            return cryptotext.equals(that.cryptotext);
        }

        @Override
        public int hashCode() {
            return Objects.hash(cryptotext);
        }

        @Override
        public String toString() {
            return "CryptotextCacheKey{cryptotext=" + cryptotext + "}";
        }
    }

    protected static class PlaintextCacheKey {
        protected final byte[] bytes;
        protected final KmsKey kmsKey;
        protected final String tenant;
        protected final String context;

        public PlaintextCacheKey(byte[] bytes, KmsKey kmsKey, String tenant, CacheContextOption contextOption) {
            this.bytes = bytes;
            this.kmsKey = requireNonNull(kmsKey);
            this.tenant = tenant;

            if (contextOption == null) {
                context = null;
            } else {
                Long entityId = contextOption.getEntityId();
                if (entityId == null || entityId == 0L) {
                    this.context = contextOption.getEntityField() + "@" + contextOption.getEntitySystemHashCode();
                } else {
                    this.context = contextOption.getEntityField() + "#" + entityId;
                }
            }
        }

        // CHECKSTYLE:OFF
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            PlaintextCacheKey that = (PlaintextCacheKey) o;
            return Arrays.equals(bytes, that.bytes) && kmsKey.equals(that.kmsKey) && Objects.equals(tenant, that.tenant) && context.equals(that.context);
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(kmsKey, tenant, context);
            result = 31 * result + Arrays.hashCode(bytes);
            return result;
        }

        @Override
        public String toString() {
            return "PlaintextCacheKey{"
                    + "plaintext=" + quote(new String(bytes))
                    + ", kmsKey=" + kmsKey
                    + ", tenant=" + quote(tenant)
                    + ", context=" + context
                    + "}";
        }
    }

    @Override
    public String toString() {
        return toSimpleString(this) + "{"
                + "provider=" + toSimpleString(provider)
                + ", plaintextCache=" + plaintextCache.size()
                + ", cryptotextCache=" + cryptotextCache.size()
                + "}";
    }
}
