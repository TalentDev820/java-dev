package com.r.crypto.api.provider;

import com.r.crypto.api.CryptoAlgorithm;
import com.r.crypto.api.CryptoOperation;

public interface LocalCryptoProvider {
    boolean supports(CryptoAlgorithm algorithm, CryptoOperation operation);
}
