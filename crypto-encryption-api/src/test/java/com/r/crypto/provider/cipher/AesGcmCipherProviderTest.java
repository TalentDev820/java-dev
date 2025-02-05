package com.r.crypto.provider.cipher;

import com.r.crypto.api.Cryptotext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Arrays;

import static com.r.crypto.util.ExceptionWrapper.wrap;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;

public class AesGcmCipherProviderTest {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final AesGcmCipherProvider provider = new AesGcmCipherProvider();

    private SecretKey key;

    @BeforeMethod
    public void beforeMethod() {
        wrap(() -> {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256);
            key = generator.generateKey();
        });
    }

    @Test
    public void encryptDecrypt() {
        verifyEncryptDecrypt(null);
        verifyEncryptDecrypt("");
        verifyEncryptDecrypt("1");
        verifyEncryptDecrypt("12");
        verifyEncryptDecrypt("123");

        long tries = 50, ops = tries*2, start = System.currentTimeMillis();
        logger.info("starting " + ops + " encrypt/decrypt operations");
        for (int i = 0; i < tries; i++) {
            byte[] plaintext = ("foobar" + i).getBytes();
            assertEquals(plaintext, provider.decrypt(provider.encrypt(plaintext, key), key));
        }

        long time = System.currentTimeMillis() - start;
        double average = time / (double) ops;
        logger.info(ops + " operations"
                + " in " + time + " ms"
                + ", average " + average + " ms/operation");
    }

    private void verifyEncryptDecrypt(String plaintext) {
        if (plaintext == null) {
            assertNull(provider.encrypt(null, key));
        } else {
            byte[] bytes = plaintext.getBytes();
            assertEquals(provider.decrypt(provider.encrypt(bytes, key), key), bytes);
        }
    }

    /** Random IV means encrypting same plaintext twice gives different results */
    @Test
    public void verifyRandomIV() {
        byte[] plaintext = "foobar".getBytes();
        Cryptotext cryptotext1 = provider.encrypt(plaintext, key);
        Cryptotext cryptotext2 = provider.encrypt(plaintext, key);
        logger.info("cryptotext1=" + cryptotext1);
        logger.info("cryptotext2=" + cryptotext2);
        assertEquals(cryptotext1.header(), cryptotext2.header());
        assertEquals(cryptotext1.getData().length, cryptotext2.getData().length);
        assertFalse(Arrays.equals(cryptotext1.getData(), cryptotext2.getData()));
        assertEquals(provider.decrypt(cryptotext1, key), plaintext);
        assertEquals(provider.decrypt(cryptotext2, key), plaintext);
        assertEquals(provider.decrypt(cryptotext1, key), provider.decrypt(cryptotext2, key));
    }

    @Test
    public void verifyDecryptWithOnlyHeaderPresent() {
        final Cryptotext cryptotext = new Cryptotext("aes", null);

        final byte[] decrypt = provider.decrypt(cryptotext, key);

        assertNull(decrypt);
    }
}
