package com.r.crypto.provider.cipher;

import com.r.crypto.api.CryptoAlgorithm;
import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.kms.ExportedKey;
import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.api.kms.LocalKms;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.api.option.TenantOption;
import com.r.crypto.encryption.api.provider.LocalEncryptionProvider;
import com.r.crypto.encryption.api.provider.RemoteEncryptionProvider;
import com.r.crypto.encryption.exception.RCryptoEncryptionException;
import com.r.crypto.util.Timer;
import com.r.crypto.util.Timer.TimedResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.r.crypto.util.Util.list;
import static com.r.crypto.util.Util.quote;
import static com.r.crypto.util.Util.toSimpleString;
import static java.util.Objects.requireNonNull;
import static org.slf4j.event.Level.INFO;

public class LocalKmsEncryptionProvider implements RemoteEncryptionProvider {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final Timer timer = new Timer(logger, INFO, RCryptoEncryptionException.class);
    private final LocalKms kms;
    private final LocalEncryptionProvider provider;

    public LocalKmsEncryptionProvider(LocalKms kms, LocalEncryptionProvider provider) {
        this.kms = kms;
        this.provider = provider;
    }

    public LocalKms getKms() {
        return kms;
    }

    public LocalEncryptionProvider getProvider() {
        return provider;
    }

    @Override
    public Cryptotext encrypt(byte[] plaintext, CryptoAlgorithm algorithm, KmsKey kmsKey, CryptoOption... options) {
        if (plaintext == null) {
            return null;
        }

        return timer.timedResult(
                () -> "encrypt kmsKey=" + quote(kmsKey) + " options=" + list(options),
                () -> {
                    requireNonNull(kmsKey);
                    ExportedKey exportedKey = kms.exportKey(kmsKey, options);
                    Cryptotext cryptotext = provider.encrypt(plaintext, algorithm, exportedKey.getKey(), options);
                    cryptotext.setKey(exportedKey.getKmsKey());
                    cryptotext.setTenant(TenantOption.findTenant(options));
                    return new TimedResult<>(cryptotext, () -> "result=" + cryptotext.toSimpleString());
                }
        );
    }

    @Override
    public byte[] decrypt(Cryptotext cryptotext, KmsKey key, CryptoOption... options) {
        if (cryptotext == null) {
            return null;
        }

        return timer.time(
                () -> "decrypt cryptotext=" + cryptotext.toSimpleString()
                        + " kmsKey=" + quote(key)
                        + " options=" + list(options),
                () -> {
                    KmsKey kmsKey = KmsKey.resolveKey(cryptotext, key);
                    CryptoOption[] resolvedOptions = TenantOption.assertTenant(cryptotext, options);
                    ExportedKey exportedKey = kms.exportKey(kmsKey, resolvedOptions);
                    return provider.decrypt(cryptotext, exportedKey.getKey(), resolvedOptions);
                }
        );
    }

    @Override
    public Integer getActiveVersion(String kmsKeyName, CryptoOption... options) {
        return timer.time(
                INFO,
                "getActiveVersion kmsKeyName=" + quote(kmsKeyName) + " options=" + list(options),
                () -> kms.getActiveVersion(kmsKeyName, options)
        );
    }

    @Override
    public ExportedKey exportKey(KmsKey kmsKey, CryptoOption... options) {
        return timer.time(
                INFO,
                "exportKey kmsKey=" + quote(kmsKey) + " options=" + list(options),
                () -> kms.exportKey(kmsKey, options)
        );
    }

    @Override
    public void rotateKey(String kmsKeyName, CryptoOption... options) {
        timer.time(
                INFO,
                "rotateKey kmsKeyName=" + quote(kmsKeyName) + " options=" + list(options),
                () -> kms.rotateKey(kmsKeyName, options)
        );
    }

    @Override
    public String toString() {
        return toSimpleString(this) + "{"
                + "kms=" + toSimpleString(kms)
                + ", provider=" + toSimpleString(provider)
                + "}";
    }
}
