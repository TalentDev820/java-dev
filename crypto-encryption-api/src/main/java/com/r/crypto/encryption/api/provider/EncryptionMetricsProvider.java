package com.r.crypto.encryption.api.provider;

import static com.r.crypto.api.option.TenantOption.findTenant;
import static com.r.crypto.encryption.api.EncryptionOperation.DECRYPT;
import static com.r.crypto.encryption.api.EncryptionOperation.ENCRYPT;
import static com.r.crypto.encryption.api.EncryptionOperation.EXPORT_KEY;
import static com.r.crypto.encryption.api.EncryptionOperation.GET_ACTIVE_KEY_VERSION;
import static com.r.crypto.encryption.api.EncryptionOperation.REWRAP;
import static com.r.crypto.encryption.api.EncryptionOperation.ROTATE_KEY;
import static com.r.crypto.util.LogUtil.trace;
import static com.r.crypto.util.Util.list;

import com.r.crypto.api.CryptoAlgorithm;
import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.kms.ExportedKey;
import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.encryption.api.EncryptionItem;
import com.r.crypto.encryption.api.EncryptionOperation;
import com.r.crypto.encryption.api.service.EncryptionMetricsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.function.Supplier;

public class EncryptionMetricsProvider implements RemoteEncryptionProvider {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final EncryptionMetricsService metricsService;
    private final RemoteEncryptionProvider provider;
    private final String providerName;

    public EncryptionMetricsProvider(EncryptionMetricsService metricsService, RemoteEncryptionProvider provider) {
        this.metricsService = metricsService;
        this.provider = provider;
        this.providerName = provider.getClass().getSimpleName();
    }

    public EncryptionMetricsService getMetricsService() {
        return metricsService;
    }

    public RemoteEncryptionProvider getProvider() {
        return provider;
    }

    public String getProviderName() {
        return providerName;
    }

    @Override
    public Cryptotext encrypt(byte[] plaintext, CryptoAlgorithm algorithm, KmsKey kmsKey, CryptoOption... options) {
        return reportMetric(ENCRYPT, kmsKey, options, () -> provider.encrypt(plaintext, algorithm, kmsKey, options));
    }

    @Override
    public byte[] decrypt(Cryptotext cryptotext, KmsKey kmsKey, CryptoOption... options) {
        return reportMetric(DECRYPT, kmsKey, options, () -> provider.decrypt(cryptotext, kmsKey, options));
    }

    @Override
    public Cryptotext encrypt(byte[] plaintext, KmsKey kmsKey, CryptoOption... options) {
        return reportMetric(ENCRYPT, kmsKey, options, () -> provider.encrypt(plaintext, kmsKey, options));
    }

    @Override
    public byte[] decrypt(Cryptotext cryptotext, CryptoOption... options) {
        return reportMetric(DECRYPT, cryptotext.getKey(), options, () -> provider.decrypt(cryptotext, options));
    }

    @Override
    public Cryptotext rewrap(Cryptotext cryptotext, CryptoOption... options) {
        return reportMetric(REWRAP, cryptotext.getKey(), options, () -> provider.rewrap(cryptotext, options));
    }

    @Override
    public ExportedKey exportKey(KmsKey kmsKey, CryptoOption... options) {
        return reportMetric(EXPORT_KEY, kmsKey, options, () -> provider.exportKey(kmsKey, options));
    }

    @Override
    public Integer getActiveVersion(String kmsKeyName, CryptoOption... options) {
        return reportMetric(
                GET_ACTIVE_KEY_VERSION,
                new KmsKey(kmsKeyName, null),
                options,
                () -> provider.getActiveVersion(kmsKeyName, options)
        );
    }

    @Override
    public void rotateKey(String kmsKeyName, CryptoOption... options) {
        reportMetric(
                ROTATE_KEY,
                new KmsKey(kmsKeyName, null),
                options,
                () -> {
                    provider.rotateKey(kmsKeyName, options);
                    return null;
                }
        );
    }

    @Override
    public boolean process(List<EncryptionItem> items, boolean batch) {
        logger.trace("process items={} batch={}", items, batch);
        if (batch) {
            return provider.process(items, batch);
        } else {
            return RemoteEncryptionProvider.super.process(items, batch);
        }
    }

    public <T> T reportMetric(EncryptionOperation operation, KmsKey kmsKey, CryptoOption[] options, Supplier<T> supplier) {
        trace(logger, () -> "reportMetric operation=" + operation + " kmsKey=" + kmsKey + " options=" + list(options));
        long startNanos = System.nanoTime();
        Throwable error = null;
        try {
            return supplier.get();
        } catch (RuntimeException | Error e) {
            error = e;
            throw e;
        } finally {
            metricsService.reportEvent(
                    providerName,
                    operation,
                    kmsKey,
                    findTenant(options),
                    System.nanoTime() - startNanos,
                    error
            );
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "{"
                + "metricsService=" + metricsService
                + ", provider=" + provider
                + "}";
    }
}
