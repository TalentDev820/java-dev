package com.r.crypto.util;

@FunctionalInterface
public interface ThrowingSupplier<T> {
    T get() throws Throwable;
}
