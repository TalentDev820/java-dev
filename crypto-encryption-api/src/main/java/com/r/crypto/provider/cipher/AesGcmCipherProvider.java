package com.r.crypto.provider.cipher;

import static com.r.crypto.encryption.api.EncryptionOperation.DECRYPT;
import static com.r.crypto.encryption.api.EncryptionOperation.ENCRYPT;
import static org.slf4j.event.Level.DEBUG;

import com.r.crypto.api.CryptoAlgorithm;
import com.r.crypto.api.CryptoOperation;
import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.encryption.api.provider.LocalEncryptionProvider;
import com.r.crypto.encryption.exception.RCryptoEncryptionException;
import com.r.crypto.util.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.security.Key;
import java.security.SecureRandom;

public class AesGcmCipherProvider implements LocalEncryptionProvider {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final Timer timer = new Timer(logger, DEBUG, RCryptoEncryptionException.class);
    private final SecureRandom secureRandom = new SecureRandom();

    protected static final CryptoAlgorithm DEFAULT_ALGORITHM = new CryptoAlgorithm("aes");

    /** Recommended IV for AES-256 is 96 bits. */
    public static final int AES_GCM_IV_SIZE_BYTES = 96 / 8;

    /** Maximum AES/GCM tag length is 128 bits. */
    public static final int AES_GCM_TAG_SIZE_BITS = 128;

    @Override
    public Cryptotext encrypt(byte[] plaintext, Key secretKey, CryptoOption... options) {
        return encrypt(plaintext, DEFAULT_ALGORITHM, secretKey, options);
    }

    @Override
    public Cryptotext encrypt(byte[] plaintext, CryptoAlgorithm algorithm, Key secretKey, CryptoOption... options) {
        if (algorithm != null && !supports(algorithm, ENCRYPT)) {
            throw new RCryptoEncryptionException("unsupported algorithm=" + algorithm);
        }

        if (plaintext == null) {
            return null;
        }

        return timer.time("encrypt", () -> {
            // Generate the IV, must be random for every invocation
            byte[] iv = new byte[AES_GCM_IV_SIZE_BYTES];
            secureRandom.nextBytes(iv);
            GCMParameterSpec spec = new GCMParameterSpec(AES_GCM_TAG_SIZE_BITS, iv);

            // Cipher output size will be plaintext size plus the GCM tag size,
            // but we prepend the IV as it needs to travel with the ciphertext
            byte[] result = new byte[AES_GCM_IV_SIZE_BYTES + plaintext.length + AES_GCM_TAG_SIZE_BITS / 8];
            System.arraycopy(iv, 0, result, 0, iv.length);

            // Encrypt and add result after the IV in the output array
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            cipher.doFinal(plaintext, 0, plaintext.length, result, AES_GCM_IV_SIZE_BYTES);
            return new Cryptotext(DEFAULT_ALGORITHM, result);
        });
    }

    @Override
    public byte[] decrypt(Cryptotext cryptotext, Key secretKey, CryptoOption... options) {
        if (cryptotext == null || cryptotext.getData() == null) {
            return null;
        }

        CryptoAlgorithm algorithm = cryptotext.getAlgorithm();
        if (algorithm != null && !supports(algorithm, DECRYPT)) {
            throw new RCryptoEncryptionException("unsupported algorithm=" + algorithm);
        }

        return timer.time("encrypt", () -> {
            // The IV is in the first AES_GCM_IV_SIZE_BYTES
            byte[] data = cryptotext.getData();
            GCMParameterSpec spec = new GCMParameterSpec(AES_GCM_TAG_SIZE_BITS, data, 0, AES_GCM_IV_SIZE_BYTES);

            // The ciphertext begins immediately after the IV and includes the tag
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            return cipher.doFinal(data, AES_GCM_IV_SIZE_BYTES, data.length - AES_GCM_IV_SIZE_BYTES);
        });
    }

    @Override
    public boolean supports(CryptoAlgorithm algorithm, CryptoOperation operation) {
        return algorithm.matches("aes[gcm,128,96]");
    }
}
