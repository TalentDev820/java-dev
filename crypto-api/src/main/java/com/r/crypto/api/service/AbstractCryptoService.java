package com.r.crypto.api.service;

import com.r.crypto.api.CryptoAlgorithm;
import com.r.crypto.api.CryptoOperation;
import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.api.provider.LocalCryptoProvider;
import com.r.crypto.api.provider.RemoteCryptoProvider;

public abstract class AbstractCryptoService
        <O extends CryptoOperation, L extends LocalCryptoProvider, R extends RemoteCryptoProvider>
        implements CryptoService {
    protected final AlgorithmManager<O, L> algorithmManager = new AlgorithmManager<>();
    protected final VirtualKeyManager<O, R> virtualKeyManager = new VirtualKeyManager<>();

    public void addAlgorithm(CryptoAlgorithm algorithm, O operation, L provider) {
        algorithmManager.addAlgorithm(algorithm, operation, provider);
    }

    public void addVirtualKeyAlias(String alias, String virtualKey) {
        virtualKeyManager.addAlias(alias, virtualKey);
    }

    public void addVirtualKeyOperation(
            String virtualKey,
            CryptoAlgorithm algorithm,
            O operation,
            R provider,
            String keyName,
            CryptoOption... options) {
        virtualKeyManager.addVirtualKeyOperation(virtualKey, algorithm, operation, provider, keyName, options);
    }

    public KmsKey getMaxVersionKey(String virtualKey, O operation, CryptoOption... options) {
        VirtualKeyOperation<O, R> config = virtualKeyManager.getConfig(virtualKey, operation);
        String kmsKeyName = config.getKmsKeyName();
        Integer maxKeyVersion = config.getProvider().getActiveVersion(kmsKeyName, options);
        return new KmsKey(kmsKeyName, maxKeyVersion);
    }

    public R getRemoteProvider(String virtualKey, O operation) {
        return virtualKeyManager.getConfig(virtualKey, operation).getProvider();
    }

    public VirtualKeyManager<O, R> getVirtualKeyManager() {
        return virtualKeyManager;
    }
}
