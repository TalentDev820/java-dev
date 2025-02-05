package com.r.crypto.encryption.utils;

import static com.r.crypto.encryption.config.EncryptionServiceConfig.PROPERTY_PREFIX;
import static java.lang.Boolean.TRUE;

import com.r.crypto.api.CryptoAlgorithm;
import com.r.crypto.api.kms.LoadingCacheKms;
import com.r.crypto.encryption.api.provider.EncryptionMetricsProvider;
import com.r.crypto.encryption.api.provider.RemoteEncryptionProvider;
import com.r.crypto.encryption.api.service.EncryptionMetricsService;
import com.r.crypto.encryption.api.service.REncryptionService;
import com.r.crypto.encryption.config.EncryptionServiceConfig;
import com.r.crypto.encryption.hibernate.DebugInterceptor;
import com.r.crypto.provider.cipher.AesGcmCipherProvider;
import com.r.crypto.provider.cipher.LocalKmsEncryptionProvider;
import com.r.crypto.service.encryption.impl.vault.VaultAesEncryptionProvider;
import com.r.crypto.util.ThrowingRunnable;
import com.r.crypto.util.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;

public class LoggingTest extends AbstractTestNGSpringContextTests {
    protected static final String NEWLINE = System.lineSeparator();
    protected final Logger logger = LoggerFactory.getLogger(getClass());
    protected final Timer timer = new Timer(logger);

    @Autowired
    protected Environment env;

    @Autowired
    protected REncryptionService encryptionService;

    @Autowired
    protected EncryptionMetricsService encryptionMetricsService;

    @BeforeClass
    public void beforeClass() {
        DebugInterceptor.reset();
        bigLog("beforeClass " + getClass().getSimpleName() + " encryptionMetricsService=" + encryptionMetricsService);
    }

    @AfterClass(alwaysRun = true)
    public void afterClass() {
        DebugInterceptor.reset();
        bigLog("afterClass " + getClass().getSimpleName());
    }

    public void bigLog(String message) {
        String dashes = repeat('=', 40);
        String prettyMessage = dashes + " " + message + " " + dashes;
        String divider = repeat('=', prettyMessage.length());
        logger.info(NEWLINE + NEWLINE
                + divider + NEWLINE
                + prettyMessage + NEWLINE
                + divider + NEWLINE);
    }

    public void execute(ThrowingRunnable runnable) {
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        StackTraceElement callerElement = stackTrace[2];
        String method = callerElement.getMethodName();
        TestUtils.execute(method, logger, runnable);
    }

    public void log(String message) {
        String dashes = repeat('=', 10);
        logger.info(NEWLINE + NEWLINE + dashes + " " + message + " " + dashes + NEWLINE);
    }

    public static String repeat(char ch, int count) {
        return String.join("", Collections.nCopies(count, String.valueOf(ch)));
    }
}
