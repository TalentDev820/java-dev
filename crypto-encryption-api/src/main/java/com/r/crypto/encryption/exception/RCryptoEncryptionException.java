package com.r.crypto.encryption.exception;

import com.r.crypto.exception.RCryptoException;

public class RCryptoEncryptionException extends RCryptoException {
    private static final long serialVersionUID = 1;

    public RCryptoEncryptionException(String message) {
        super(message);
    }

    public RCryptoEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    public RCryptoEncryptionException(Throwable cause) {
        super(cause);
    }
}
