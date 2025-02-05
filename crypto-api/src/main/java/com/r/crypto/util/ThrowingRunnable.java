package com.r.crypto.util;

@FunctionalInterface
public interface ThrowingRunnable {
    void run() throws Throwable;
}
