package com.r.crypto.exception;

public class RCryptoInvalidKeyException extends RCryptoException {
    private static final long serialVersionUID = 1;

    public RCryptoInvalidKeyException(String message) {
        super(message);
    }

    public RCryptoInvalidKeyException(String message, Throwable cause) {
        super(message, cause);
    }

    public RCryptoInvalidKeyException(Throwable cause) {
        super(cause);
    }
}
