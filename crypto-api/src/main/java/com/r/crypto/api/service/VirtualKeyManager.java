package com.r.crypto.api.service;

import com.r.crypto.api.CryptoAlgorithm;
import com.r.crypto.api.CryptoOperation;
import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.api.provider.RemoteCryptoProvider;
import com.r.crypto.exception.RCryptoInvalidKeyException;
import com.r.crypto.exception.RCryptoMissingKeyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static com.r.crypto.util.Util.toSimpleString;

public class VirtualKeyManager<O extends CryptoOperation, R extends RemoteCryptoProvider> {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final Map<String, String> aliases = new HashMap<>();
    private final Map<String, VirtualKeyConfig<O, R>> virtualKeys = new HashMap<>();
    private final Map<String, String> kmsKeyNames = new HashMap<>();

    public void addAlias(String virtualKey, String... aliases) {
        Arrays.stream(aliases).forEach(alias -> this.aliases.put(alias, virtualKey));
    }

    public void addVirtualKeyOperation(
            String virtualKey,
            CryptoAlgorithm algorithm,
            O operation,
            R provider,
            String kmsKeyName,
            CryptoOption... options) {
        virtualKeys.computeIfAbsent(virtualKey, key -> new VirtualKeyConfig<>(key, algorithm));
        virtualKeys.get(virtualKey).addOperation(operation, provider, kmsKeyName, options);
        kmsKeyNames.put(kmsKeyName, virtualKey);
    }

    public VirtualKeyOperation<O, R> getConfig(String virtualKey, O operation) {
        String resolvedVirtualKey = aliases.getOrDefault(virtualKey, virtualKey);
        VirtualKeyConfig<O, R> config = virtualKeys.get(resolvedVirtualKey);
        if (config == null) {
            throw new RCryptoMissingKeyException("virtualKey=" + virtualKey + " not found");
        }

        VirtualKeyOperation<O, R> keyOperation = config.getOperation(operation);
        if (keyOperation == null) {
            throw new RCryptoInvalidKeyException("virtualKey=" + virtualKey + " not configured for operation=" + operation);
        }

        return keyOperation;
    }

    public VirtualKeyOperation<O, R> getConfig(KmsKey kmsKey, O operation) {
        String virtualKey = kmsKeyNames.get(kmsKey.getName());
        if (virtualKey == null) {
            throw new RCryptoMissingKeyException("kmsKey=" + kmsKey + " not found");
        }
        return getConfig(virtualKey, operation);
    }

    public R getProvider(KmsKey kmsKey, O operation) {
        return getConfig(kmsKeyNames.get(kmsKey.getName()), operation).getProvider();
    }

    public <T> T withVirtualKey(String virtualKey, O operation, VirtualKeyCommand<T, R> command) {
        VirtualKeyOperation<O, R> config = getConfig(virtualKey, operation);
        return command.execute(config.getAlgorithm(), config.getProvider(), new KmsKey(config.getKmsKeyName()));
    }

    public interface VirtualKeyCommand<T, R> {
        T execute(CryptoAlgorithm algorithm, R provider, KmsKey key);
    }

    @Override
    public String toString() {
        return toSimpleString(this) + "{"
                + "aliases=" + aliases
                + ", virtualKeys=" + virtualKeys
                + ", kmsKeyNames=" + kmsKeyNames
                + "}";
    }
}
