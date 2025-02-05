package com.r.crypto.exception;

public class RCryptoConsistencyException extends RCryptoException {
    private static final long serialVersionUID = 1;

    public RCryptoConsistencyException(String message) {
        super(message);
    }

    public RCryptoConsistencyException(String message, Throwable cause) {
        super(message, cause);
    }

    public RCryptoConsistencyException(Throwable cause) {
        super(cause);
    }
}
