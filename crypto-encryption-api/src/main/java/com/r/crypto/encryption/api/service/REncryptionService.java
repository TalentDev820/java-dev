package com.r.crypto.encryption.api.service;

import com.r.crypto.api.CryptoAlgorithm;
import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.api.service.AbstractCryptoService;
import com.r.crypto.api.service.VirtualKeyOperation;
import com.r.crypto.encryption.api.EncryptionItem;
import com.r.crypto.encryption.api.EncryptionOperation;
import com.r.crypto.encryption.api.provider.LocalEncryptionProvider;
import com.r.crypto.encryption.api.provider.RemoteEncryptionProvider;
import com.r.crypto.encryption.exception.RCryptoEncryptionException;
import com.r.crypto.util.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.r.crypto.encryption.api.EncryptionOperation.DECRYPT;
import static com.r.crypto.encryption.api.EncryptionOperation.ENCRYPT;
import static com.r.crypto.encryption.api.EncryptionOperation.REWRAP;
import static com.r.crypto.util.Util.isEmpty;
import static com.r.crypto.util.Util.toSimpleString;
import static org.slf4j.event.Level.DEBUG;
import static org.slf4j.event.Level.INFO;

public class REncryptionService
        extends AbstractCryptoService<EncryptionOperation, LocalEncryptionProvider, RemoteEncryptionProvider>
        implements EncryptionService {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final Timer timer = new Timer(logger, INFO, RCryptoEncryptionException.class);

    public void addSymmetricKey(
            String virtualKey,
            CryptoAlgorithm algorithm,
            RemoteEncryptionProvider provider,
            String kmsKeyName,
            CryptoOption... options
    ) {
        addVirtualKeyOperation(virtualKey, algorithm, ENCRYPT, provider, kmsKeyName, options);
        addVirtualKeyOperation(virtualKey, algorithm, DECRYPT, provider, kmsKeyName, options);
        addVirtualKeyOperation(virtualKey, algorithm, REWRAP, provider, kmsKeyName, options);
    }

    @Override
    public Cryptotext encrypt(byte[] plaintext, String virtualKey, CryptoOption... options) throws RCryptoEncryptionException {
        return virtualKeyManager.withVirtualKey(virtualKey, ENCRYPT, (algorithm, provider, key) ->
                provider.encrypt(plaintext, algorithm, key, options)
        );
    }

    @Override
    public Cryptotext encrypt(byte[] plaintext, Key key, CryptoOption... options) throws RCryptoEncryptionException {
        return encrypt(plaintext, key, new CryptoAlgorithm(key.getAlgorithm()), options);
    }

    @Override
    public Cryptotext encrypt(byte[] plaintext, Key key, CryptoAlgorithm algorithm, CryptoOption... options) throws RCryptoEncryptionException {
        return algorithmManager.getProvider(algorithm, ENCRYPT).encrypt(plaintext, algorithm, key, options);
    }

    @Override
    public byte[] decrypt(Cryptotext cryptotext, CryptoOption... options) throws RCryptoEncryptionException {
        return cryptotext == null
                ? null
                : virtualKeyManager.getProvider(cryptotext.getKey(), DECRYPT).decrypt(cryptotext, options);
    }

    @Override
    public byte[] decrypt(byte[] cryptotextData, String virtualKey, CryptoOption... options) throws RCryptoEncryptionException {
        return virtualKeyManager.withVirtualKey(virtualKey, DECRYPT, (algorithm, provider, key) ->
                provider.decrypt(new Cryptotext(algorithm, cryptotextData), key, options)
        );
    }

    @Override
    public byte[] decrypt(byte[] cryptotextData, Key key, CryptoOption... options) throws RCryptoEncryptionException {
        return decrypt(cryptotextData, key, new CryptoAlgorithm(key.getAlgorithm()), options);
    }

    @Override
    public byte[] decrypt(byte[] cryptotextData, Key key, CryptoAlgorithm algorithm, CryptoOption... options) throws RCryptoEncryptionException {
        return algorithmManager.getProvider(algorithm, ENCRYPT).decrypt(new Cryptotext(algorithm, cryptotextData), key, options);
    }

    @Override
    public Cryptotext rewrap(Cryptotext cryptotext, CryptoOption... options) {
        if (cryptotext == null) {
            return null;
        }
        return virtualKeyManager.getProvider(cryptotext.getKey(), REWRAP).rewrap(cryptotext, options);
    }

    @Override
    public void rotateKey(String virtualKey, CryptoOption... options) {
        virtualKeyManager.withVirtualKey(virtualKey, ENCRYPT, (algorithm, provider, key) -> {
            provider.rotateKey(key.getName(), options);
            return null;
        });
    }

    @Override
    public boolean process(Collection<EncryptionItem> items, boolean batch) {
        if (isEmpty(items)) {
            return true;
        }

        return timer.bracketTime(DEBUG, "%s items=%d", batch ? "batch" : "process", items.size(), () -> {
            Map<RemoteEncryptionProvider, List<EncryptionItem>> providerBatchMap = new HashMap<>();

            // Sort items by provider, which is determined by the virtual key and operation
            items.stream().filter(item -> !item.processed()).forEach(item -> {
                try {
                    final VirtualKeyOperation<EncryptionOperation, RemoteEncryptionProvider> config;
                    switch (item.getOperation()) {
                        case ENCRYPT:
                            config = virtualKeyManager.getConfig(item.getVirtualKey(), ENCRYPT);
                            item.setKmsKey(new KmsKey(config.getKmsKeyName()));
                            break;
                        case DECRYPT:
                            config = virtualKeyManager.getConfig(item.getKmsKey(), DECRYPT);
                            break;
                        case REWRAP:
                            config = virtualKeyManager.getConfig(item.getKmsKey(), REWRAP);
                            break;
                        default:
                            throw new IllegalStateException("unsupported batch operation=" + item.getOperation());
                    }
                    providerBatchMap.computeIfAbsent(config.getProvider(), p -> new ArrayList<>()).add(item);
                } catch (Throwable t) {
                    logger.error(t + " finding virtual key configuration", t);
                    RCryptoEncryptionException exception = t instanceof RCryptoEncryptionException
                            ? (RCryptoEncryptionException) t
                            : new RCryptoEncryptionException(t);
                    item.setException(exception);
                }
            });

            boolean success = true;
            for (Map.Entry<RemoteEncryptionProvider, List<EncryptionItem>> entry : providerBatchMap.entrySet()) {
                RemoteEncryptionProvider provider = entry.getKey();
                List<EncryptionItem> providerItems = entry.getValue();
                success = provider.process(providerItems, batch) && success;
            }
            return success;
        });
    }

    @Override
    public String toString() {
        return toSimpleString(this) + "{"
                + "algorithmManager=" + algorithmManager
                + ", virtualKeyManager=" + virtualKeyManager
                + "}";
    }
}
