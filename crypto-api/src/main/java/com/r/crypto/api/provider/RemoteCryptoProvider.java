package com.r.crypto.api.provider;

import com.r.crypto.api.kms.ExportedKey;
import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.api.option.CryptoOption;

public interface RemoteCryptoProvider {
    Integer getActiveVersion(String kmsKeyName, CryptoOption... options);

    ExportedKey exportKey(KmsKey kmsKey, CryptoOption... options);

    void rotateKey(String kmsKeyName, CryptoOption... options);
}
