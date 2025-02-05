package com.r.crypto.api.service;

import com.r.crypto.api.provider.CryptoProvider;

public class VirtualKeyOperationConfig<P extends CryptoProvider> {
    private final String kmsKeyName;
    private final P provider;

    public VirtualKeyOperationConfig(String kmsKeyName, P provider) {
        this.kmsKeyName = kmsKeyName;
        this.provider = provider;
    }

    public String getKmsKeyName() {
        return kmsKeyName;
    }

    public P getProvider() {
        return provider;
    }
}
