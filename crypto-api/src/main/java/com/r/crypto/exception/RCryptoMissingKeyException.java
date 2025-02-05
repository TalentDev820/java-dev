package com.r.crypto.exception;

public class RCryptoMissingKeyException extends RCryptoException {
    private static final long serialVersionUID = 1;

    public RCryptoMissingKeyException(String message) {
        super(message);
    }

    public RCryptoMissingKeyException(String message, Throwable cause) {
        super(message, cause);
    }

    public RCryptoMissingKeyException(Throwable cause) {
        super(cause);
    }
}
