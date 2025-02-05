package com.r.crypto.api.service;

import com.r.crypto.api.CryptoAlgorithm;
import com.r.crypto.api.CryptoOperation;
import com.r.crypto.api.provider.LocalCryptoProvider;

import java.util.HashMap;
import java.util.Map;

import static com.r.crypto.util.Util.toSimpleString;

public class AlgorithmManager<O extends CryptoOperation, L extends LocalCryptoProvider> {
    private final Map<CryptoAlgorithm, Map<O, L>> algorithmsMap = new HashMap<>();

    public void addAlgorithm(CryptoAlgorithm algorithm, O operation, L provider) {
        algorithmsMap.computeIfAbsent(algorithm, a -> new HashMap<>());
        algorithmsMap.get(algorithm).put(operation, provider);
    }

    public L getProvider(CryptoAlgorithm algorithm, O operation) {
        return algorithmsMap.get(algorithm).get(operation);
    }

    @Override
    public String toString() {
        return toSimpleString(this) + "{"
                + "algorithms=" + algorithmsMap.keySet()
                + "}";
    }
}
