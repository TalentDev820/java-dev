package com.r.crypto.encryption.api.service;

import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.encryption.api.EncryptionOperation;

public interface EncryptionMetricsService {
    void reportEvent(
            String providerName,
            EncryptionOperation operation,
            KmsKey kmsKey,
            String tenant,
            long nanoTime,
            Throwable error
    );
}
