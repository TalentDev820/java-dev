package com.r.crypto.util;

public class ExceptionWrapper {
    public static void wrap(ThrowingRunnable runnable) {
        wrap(RuntimeException.class, runnable);
    }

    public static void wrap(Class<? extends RuntimeException> wrapExceptionClass, ThrowingRunnable runnable) {
        try {
            runnable.run();
        } catch (Throwable t) {
            throw wrapException(t, wrapExceptionClass);
        }
    }

    public static <T> T wrap(ThrowingSupplier<T> supplier) {
        return wrap(RuntimeException.class, supplier);
    }

    public static <T> T wrap(Class<? extends RuntimeException> wrapExceptionClass, ThrowingSupplier<T> supplier) {
        try {
            return supplier.get();
        } catch (Throwable t) {
            throw wrapException(t, wrapExceptionClass);
        }
    }

    public static RuntimeException wrapException(Throwable t, Class<? extends RuntimeException> wrapExceptionClass) {
        if (wrapExceptionClass.isAssignableFrom(t.getClass())) {
            return (RuntimeException) t;
        }

        try {
            return wrapExceptionClass.getConstructor(Throwable.class).newInstance(t);
        } catch (Exception e) {
            throw new RuntimeException(e + " trying to wrap original throwable", t);
        }
    }
}
