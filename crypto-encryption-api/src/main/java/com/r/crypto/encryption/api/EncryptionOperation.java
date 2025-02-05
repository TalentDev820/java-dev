package com.r.crypto.encryption.api;

import com.r.crypto.api.CryptoOperation;

public enum EncryptionOperation implements CryptoOperation {
    ENCRYPT,
    DECRYPT,
    REWRAP,
    GET_ACTIVE_KEY_VERSION,
    ROTATE_KEY,
    EXPORT_KEY
}
