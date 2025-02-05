package com.r.crypto.util;

import org.slf4j.Logger;
import org.slf4j.event.Level;

import java.util.function.Supplier;

import static org.slf4j.event.Level.DEBUG;
import static org.slf4j.event.Level.ERROR;
import static org.slf4j.event.Level.INFO;
import static org.slf4j.event.Level.TRACE;

/**
 * SLF4J API sucks. This class exists to mimic java.util.Logger behavior.
 */
public class LogUtil {
    public static void log(Logger logger, Level level, String s, Object... args) {
        // Another reason to use JUL instead of SLF4J logger
        switch (level) {
            case TRACE:
                logger.trace(s, args);
                break;
            case DEBUG:
                logger.debug(s, args);
                break;
            case INFO:
                logger.info(s, args);
                break;
            case WARN:
                logger.warn(s, args);
                break;
            case ERROR:
                logger.error(s, args);
                break;
            default:
                throw new IllegalStateException("unknown level=" + level);
        }
    }

    public static void log(Logger logger, Level level, Supplier<String> supplier) {
        // reasonsToHateLog4j++
        if (isEnabled(logger, level)) {
            log(logger, level, supplier.get());
        }
    }

    public static void trace(Logger logger, Supplier<String> supplier) {
        log(logger, TRACE, supplier);
    }

    public static void debug(Logger logger, Supplier<String> supplier) {
        log(logger, DEBUG, supplier);
    }

    public static void info(Logger logger, Supplier<String> supplier) {
        log(logger, INFO, supplier);
    }

    public static void error(Logger logger, Supplier<String> supplier) {
        log(logger, ERROR, supplier);
    }

    public static boolean isEnabled(Logger logger, Level level) {
        if (logger == null || level == null) {
            return false;
        }

        // reasonsToHateLog4j++
        switch (level) {
            case TRACE:
                return logger.isTraceEnabled();
            case DEBUG:
                return logger.isDebugEnabled();
            case INFO:
                return logger.isInfoEnabled();
            case WARN:
                return logger.isWarnEnabled();
            case ERROR:
                return logger.isErrorEnabled();
            default:
                throw new IllegalStateException("unknown level=" + level);
        }
    }
}
