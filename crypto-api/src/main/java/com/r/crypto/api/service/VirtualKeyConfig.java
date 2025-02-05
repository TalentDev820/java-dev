package com.r.crypto.api.service;

import com.r.crypto.api.CryptoAlgorithm;
import com.r.crypto.api.CryptoOperation;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.api.provider.RemoteCryptoProvider;

import java.util.HashMap;
import java.util.Map;

import static com.r.crypto.util.Util.quote;

public class VirtualKeyConfig<O extends CryptoOperation, R extends RemoteCryptoProvider> {
    private final String virtualKey;
    private final CryptoAlgorithm algorithm;
    private final Map<O, VirtualKeyOperation<O, R>> operations = new HashMap<>();

    public VirtualKeyConfig(String virtualKey, CryptoAlgorithm algorithm) {
        this.virtualKey = virtualKey;
        this.algorithm = algorithm;
    }

    public String getVirtualKey() {
        return virtualKey;
    }

    public CryptoAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void addOperation(O operation, R provider, String kmsKeyName, CryptoOption... options) {
        operations.put(operation, new VirtualKeyOperation<>(algorithm, operation, provider, kmsKeyName, options));
    }

    public VirtualKeyOperation<O, R> getOperation(O operation) {
        return operations.get(operation);
    }

    public Map<O, VirtualKeyOperation<O, R>> getOperations() {
        return operations;
    }

    @Override
    public String toString() {
        return "VirtualKeyConfig{"
                + "virtualKey=" + quote(virtualKey)
                + ", algorithm=" + algorithm
                + ", operations=" + operations
                + "}";
    }
}
