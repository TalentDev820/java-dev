package com.r.crypto.util;

import static com.r.crypto.util.ExceptionWrapper.wrapException;
import static com.r.crypto.util.LogUtil.isEnabled;
import static com.r.crypto.util.LogUtil.log;
import static com.r.crypto.util.Util.quote;
import static org.slf4j.event.Level.DEBUG;
import static org.slf4j.event.Level.ERROR;

import org.slf4j.Logger;
import org.slf4j.event.Level;

import java.util.function.Supplier;

public class Timer {
    private final Logger logger;
    private final Level defaultLevel;
    private final Class<? extends RuntimeException> wrapException;

    public Timer(Logger logger) {
        this(logger, DEBUG, RuntimeException.class);
    }

    public Timer(Logger logger, Class<? extends RuntimeException> wrapException) {
        this(logger, DEBUG, wrapException);
    }

    public Timer(Logger logger, Level defaultLevel, Class<? extends RuntimeException> wrapException) {
        this.logger = logger;
        this.defaultLevel = defaultLevel;
        this.wrapException = wrapException;
    }

    public Logger getLogger() {
        return logger;
    }

    public void time(String operation, ThrowingRunnable runnable) {
        doTime(defaultLevel, "", () -> operation, "", runnable);
    }

    public void time(String operation, Object param, ThrowingRunnable runnable) {
        doTime(defaultLevel, "", () -> String.format(operation, param), "", runnable);
    }

    public void time(Level level, String operation, ThrowingRunnable runnable) {
        doTime(level, "", () -> operation, "", runnable);
    }

    public void time(Level level, String operation, Object param, ThrowingRunnable runnable) {
        doTime(level, "", () -> String.format(operation, param), "", runnable);
    }

    public void time(Level level, String operation, Object[] params, ThrowingRunnable runnable) {
        doTime(level, "", () -> String.format(operation, params), "", runnable);
    }

    public void time(Supplier<String> operationSupplier, ThrowingRunnable runnable) {
        doTime(defaultLevel, "", operationSupplier, "", runnable);
    }

    public void time(Level level, Supplier<String> operationSupplier, ThrowingRunnable runnable) {
        doTime(level, "", operationSupplier, "", runnable);
    }

    public <T> T time(String operation, ThrowingSupplier<T> supplier) {
        return doTime(defaultLevel, "", () -> operation, "", supplier);
    }

    public <T> T time(String operation, Object param, ThrowingSupplier<T> supplier) {
        return doTime(defaultLevel, "", () -> String.format(operation, param), "", supplier);
    }

    public <T> T time(Level level, String operation, ThrowingSupplier<T> supplier) {
        return doTime(level, "", () -> operation, "", supplier);
    }

    public <T> T time(Level level, String operation, Object param, ThrowingSupplier<T> supplier) {
        return doTime(level, "", () -> String.format(operation, param), "", supplier);
    }

    public <T> T time(Supplier<String> operationSupplier, ThrowingSupplier<T> supplier) {
        return doTime(defaultLevel, "", operationSupplier, "", supplier);
    }

    public <T> T time(Level level, Supplier<String> operationSupplier, ThrowingSupplier<T> supplier) {
        return doTime(level, "", operationSupplier, "", supplier);
    }

    public void bracketTime(String operation, ThrowingRunnable runnable) {
        bracketTime(defaultLevel, () -> operation, runnable);
    }

    public void bracketTime(Level level, String operation, ThrowingRunnable runnable) {
        bracketTime(level, () -> operation, runnable);
    }

    public void bracketTime(Level level, String operation, Object param, ThrowingRunnable runnable) {
        bracketTime(level, () -> String.format(operation, param), runnable);
    }

    public void bracketTime(Level level, String operation, Object param1, Object param2, ThrowingRunnable runnable) {
        bracketTime(level, () -> String.format(operation, param1, param2), runnable);
    }

    public void bracketTime(Level level, String operation, Object param1, Object param2, Object param3, ThrowingRunnable runnable) {
        bracketTime(level, () -> String.format(operation, param1, param2, param3), runnable);
    }

    public void bracketTime(String operation, Object param, ThrowingRunnable runnable) {
        bracketTime(defaultLevel, () -> String.format(operation, param), runnable);
    }

    public void bracketTime(String operation, Object param1, Object param2, ThrowingRunnable runnable) {
        bracketTime(defaultLevel, () -> String.format(operation, param1, param2), runnable);
    }

    public void bracketTime(String operation, Object param1, Object param2, Object param3, ThrowingRunnable runnable) {
        bracketTime(defaultLevel, () -> String.format(operation, param1, param2, param3), runnable);
    }

    public void bracketTime(Level level, Supplier<String> operationSupplier, ThrowingRunnable runnable) {
        if (isEnabled(logger, level)) {
            int timerId = Math.abs(System.identityHashCode(new Object()) + (int) System.nanoTime());
            log(logger, level, "timer: starting operation={} timerId={}", operationSupplier.get(), timerId);
            doTime(level, "finished ", operationSupplier, " timerId=" + timerId, runnable);
        } else {
            doTime(level, "finished ", operationSupplier, "", runnable);
        }
    }

    public <T> T bracketTime(String operation, ThrowingSupplier<T> supplier) {
        return bracketTime(defaultLevel, () -> operation, supplier);
    }

    public <T> T bracketTime(String operation, Object param, ThrowingSupplier<T> supplier) {
        return bracketTime(defaultLevel, () -> String.format(operation, param), supplier);
    }

    public <T> T bracketTime(String operation, Object param1, Object param2, ThrowingSupplier<T> supplier) {
        return bracketTime(defaultLevel, () -> String.format(operation, param1, param2), supplier);
    }

    public <T> T bracketTime(String operation, Object param1, Object param2, Object param3, ThrowingSupplier<T> supplier) {
        return bracketTime(defaultLevel, () -> String.format(operation, param1, param2, param3), supplier);
    }

    public <T> T bracketTime(Level level, String operation, ThrowingSupplier<T> supplier) {
        return bracketTime(level, () -> operation, supplier);
    }

    public <T> T bracketTime(Level level, String operation, Object param, ThrowingSupplier<T> supplier) {
        return bracketTime(level, () -> String.format(operation, param), supplier);
    }

    public <T> T bracketTime(Level level, String operation, Object param1, Object param2, ThrowingSupplier<T> supplier) {
        return bracketTime(level, () -> String.format(operation, param1, param2), supplier);
    }

    public <T> T bracketTime(Level level, String operation, Object param1, Object param2, Object param3, ThrowingSupplier<T> supplier) {
        return bracketTime(level, () -> String.format(operation, param1, param2, param3), supplier);
    }

    public <T> T bracketTime(Supplier<String> operationSupplier, ThrowingSupplier<T> supplier) {
        return bracketTime(defaultLevel, operationSupplier, supplier);
    }

    public <T> T bracketTime(Level level, Supplier<String> messageSupplier, ThrowingSupplier<T> supplier) {
        if (isEnabled(logger, level)) {
            int timerId = Math.abs(System.identityHashCode(new Object()) + (int) System.nanoTime());
            String operation = messageSupplier.get();
            log(logger, level, "timer: starting operation={} timerId={}", operation, timerId);
            return doTime(level, "finished ", operation, " timerId=" + timerId, supplier);
        } else {
            return doTime(level, "finished ", messageSupplier, "", supplier);
        }
    }

    private void doTime(Level level, String prefix, String message, String suffix, ThrowingRunnable runnable) {
        doTime(level, prefix, () -> message, suffix, runnable);
    }

    private void doTime(Level level, String prefix, Supplier<String> messageSupplier, String suffix, ThrowingRunnable runnable) {
        doTime(level, prefix, messageSupplier, suffix, () -> {
            runnable.run();
            return null;
        });
    }

    private <T> T doTime(Level level, String prefix, String message, String suffix, ThrowingSupplier<T> supplier) {
        return doTime(level, prefix, () -> message, suffix, supplier);
    }

    private <T> T doTime(Level level, String prefix, Supplier<String> operationSupplier, String suffix, ThrowingSupplier<T> supplier) {
        long start = System.nanoTime();
        Throwable error = null;
        try {
            return supplier.get();
        } catch (Throwable t) {
            error = t;
            level = ERROR;
            prefix = "failed ";
            throw wrapException(t, wrapException);
        } finally {
            if (isEnabled(logger, level)) {
                String operation = operationSupplier.get();
                String errorString = (error == null) ? "" : " error=" + quote(error.getClass().getSimpleName());
                double time = (System.nanoTime() - start) / 1_000_000D;
                log(logger, level, "timer: {}operation={}{}{} time={}", prefix, operation, suffix, errorString, time);
            }
        }
    }

    public <T> T timedResult(String operation, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        return timedResult(defaultLevel, () -> operation, resultSupplier);
    }

    public <T> T timedResult(Level level, String operation, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        return timedResult(level, () -> operation, resultSupplier);
    }

    public <T> T timedResult(String operation, Object param, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        return timedResult(defaultLevel, () -> String.format(operation, param), resultSupplier);
    }

    public <T> T timedResult(String operation, Object param1, Object param2, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        return timedResult(defaultLevel, () -> String.format(operation, param1, param2), resultSupplier);
    }

    public <T> T timedResult(String operation, Object param1, Object param2, Object param3, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        return timedResult(defaultLevel, () -> String.format(operation, param1, param2, param3), resultSupplier);
    }

    public <T> T timedResult(Level level, String operation, Object param, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        return timedResult(level, () -> String.format(operation, param), resultSupplier);
    }

    public <T> T timedResult(Level level, String operation, Object param1, Object param2, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        return timedResult(level, () -> String.format(operation, param1, param2), resultSupplier);
    }

    public <T> T timedResult(
            Level level,
            String operation,
            Object param1,
            Object param2,
            Object param3,
            ThrowingSupplier<TimedResult<T>> resultSupplier
    ) {
        return timedResult(level, () -> String.format(operation, param1, param2, param3), resultSupplier);
    }

    public <T> T timedResult(Supplier<String> operationSupplier, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        return timedResult(defaultLevel, operationSupplier, resultSupplier);
    }

    public <T> T timedResult(Level level, Supplier<String> operationSupplier, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        long start = System.nanoTime();
        Throwable error = null;
        TimedResult<T> result = null;
        try {
            result = resultSupplier.get();
            return result == null ? null : result.result;
        } catch (Throwable t) {
            error = t;
            throw wrapException(t, wrapException);
        } finally {
            String prefix = "";
            if (error != null) {
                level = ERROR;
                prefix = "failed ";
            }
            if (isEnabled(logger, level)) {
                String operation = operationSupplier.get();
                if (result != null) {
                    operation = operation + " " + result.supplier.get();
                }

                String errorString = error == null ? "" : " error=" + quote(error.getClass().getSimpleName());
                String time = String.valueOf((System.nanoTime() - start) / 1_000_000D);

                log(logger, level, "timer: {}operation={}{} time={}", prefix, operation, errorString, time);
            }
        }
    }

    public <T> T bracketTimedResult(String operation, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        return bracketTimedResult(defaultLevel, () -> operation, resultSupplier);
    }

    public <T> T bracketTimedResult(String operation, Object param, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        return bracketTimedResult(defaultLevel, () -> String.format(operation, param), resultSupplier);
    }

    public <T> T bracketTimedResult(String operation, Object param1, Object param2, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        return bracketTimedResult(defaultLevel, () -> String.format(operation, param1, param2), resultSupplier);
    }

    public <T> T bracketTimedResult(String operation, Object param1, Object param2, Object param3, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        return bracketTimedResult(defaultLevel, () -> String.format(operation, param1, param2, param3), resultSupplier);
    }

    public <T> T bracketTimedResult(Level level, String operation, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        return bracketTimedResult(level, () -> operation, resultSupplier);
    }

    public <T> T bracketTimedResult(Level level, String operation, Object param, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        return bracketTimedResult(level, () -> String.format(operation, param), resultSupplier);
    }

    public <T> T bracketTimedResult(Level level, String operation, Object param1, Object param2, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        return bracketTimedResult(level, () -> String.format(operation, param1, param2), resultSupplier);
    }

    public <T> T bracketTimedResult(
            Level level,
            String operation,
            Object param1,
            Object param2,
            Object param3,
            ThrowingSupplier<TimedResult<T>> resultSupplier
    ) {
        return bracketTimedResult(level, () -> String.format(operation, param1, param2, param3), resultSupplier);
    }

    public <T> T bracketTimedResult(Level level, Supplier<String> operationSupplier, ThrowingSupplier<TimedResult<T>> resultSupplier) {
        String operation = null;
        boolean loggingEnabled = isEnabled(logger, level);

        if (loggingEnabled) {
            int timerId = Math.abs(System.identityHashCode(new Object()) + (int) System.nanoTime());
            operation = operationSupplier.get() + " timerId=" + timerId;
            log(logger, level, "timer: starting operation={}", operation);
        }

        long start = System.nanoTime();
        Throwable error = null;
        TimedResult<T> result = null;
        try {
            result = resultSupplier.get();
            return result == null ? null : result.result;
        } catch (Throwable t) {
            error = t;
            throw wrapException(t, wrapException);
        } finally {
            String prefix = "finished";
            if (error != null) {
                level = ERROR;
                prefix = "failed";
            }
            if (loggingEnabled) {
                if (result != null) {
                    operation = operation + " " + result.supplier.get();
                }

                String errorString = error == null ? "" : " error=" + quote(error.getClass().getSimpleName());
                String time = String.valueOf((System.nanoTime() - start) / 1_000_000D);
                log(logger, level, "timer: {} operation={}{} time={}", prefix, operation, errorString, time);
            }
        }
    }

    public static class TimedResult<T> {
        private final T result;
        private final Supplier<CharSequence> supplier;

        public TimedResult(T result, String operation, Object... params) {
            this.result = result;
            this.supplier = () -> String.format(operation, params);
        }

        public TimedResult(T result, Supplier<CharSequence> supplier) {
            this.result = result;
            this.supplier = supplier;
        }
    }

    public void wrap(ThrowingRunnable runnable) {
        ExceptionWrapper.wrap(wrapException, runnable);
    }

    public <T> T wrap(ThrowingSupplier<T> supplier) {
        return ExceptionWrapper.wrap(wrapException, supplier);
    }
}
