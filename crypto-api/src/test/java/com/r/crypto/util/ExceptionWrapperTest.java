package com.r.crypto.util;

import com.r.crypto.exception.RCryptoException;
import org.testng.annotations.Test;

import static org.testng.Assert.assertSame;

public class ExceptionWrapperTest {
    @Test
    public void wrapSameException() {
        RuntimeException exception = new RuntimeException("hi there");
        try {
            ExceptionWrapper.wrap(() -> { throw exception; });
        } catch (RuntimeException e) {
            assertSame(exception, e);
        }
    }

    @Test
    public void wrapExceptionSubclass() {
        IllegalStateException exception = new IllegalStateException("hi there");
        try {
            ExceptionWrapper.wrap(() -> { throw exception; });
        } catch (IllegalStateException e) {
            assertSame(exception, e);
        }
    }

    @Test
    public void wrapDifferentException() {
        RuntimeException exception = new RuntimeException("hi there");
        try {
            ExceptionWrapper.wrap(RCryptoException.class, () -> { throw exception; });
        } catch (RCryptoException e) {
            assertSame(e.getCause(), exception);
        }
    }
}
