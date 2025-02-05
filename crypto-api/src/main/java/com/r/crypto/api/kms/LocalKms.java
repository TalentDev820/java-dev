package com.r.crypto.api.kms;

import com.r.crypto.api.option.CryptoOption;

public interface LocalKms {
    Integer getActiveVersion(String keyName, CryptoOption... options);

    ExportedKey exportKey(KmsKey kmsKey, CryptoOption... options);

    void rotateKey(String kmsKeyName, CryptoOption... options);
}
