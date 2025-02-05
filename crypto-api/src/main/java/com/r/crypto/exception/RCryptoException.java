package com.r.crypto.exception;

public class RCryptoException extends RuntimeException {
    private static final long serialVersionUID = 1;

    public RCryptoException(String message) {
        super(message);
    }

    public RCryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    public RCryptoException(Throwable cause) {
        super(cause);
    }
}
