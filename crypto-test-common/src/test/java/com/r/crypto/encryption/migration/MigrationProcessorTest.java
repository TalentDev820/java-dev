package com.r.crypto.encryption.migration;

import static com.r.crypto.encryption.migration.MigrationMode.DUAL_WRITE;
import static com.r.crypto.encryption.migration.MigrationMode.ENCRYPT;
import static com.r.crypto.encryption.migration.MigrationMode.PLAINTEXT;
import static com.r.crypto.util.ExceptionWrapper.wrap;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.singletonList;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.api.option.KeySupplierOption;
import com.r.crypto.api.option.TenantOption;
import com.r.crypto.encryption.api.service.REncryptionService;
import com.r.crypto.encryption.hibernate.test.TestPersistenceConfig;
import com.r.crypto.encryption.utils.LoggingTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.ContextConfiguration;
import org.testng.annotations.Test;

import javax.crypto.KeyGenerator;
import java.util.List;

@ContextConfiguration(classes = TestPersistenceConfig.class)
public class MigrationProcessorTest extends LoggingTest {
    @Autowired
    private REncryptionService encryptionService;

    @Value("${rnet.encryption.batchEncryption.enabled:false}")
    private boolean batchEncryptionEnabled;

    private final TenantOption tenantOption = new TenantOption("migrationProcessorTestTenant");

    @Test
    public void verifyDualWrites() {
        checkVerifyReads(null, null, null, null);               // nothing to do
        checkVerifyReads("foo", null, "foo", null);             // no ciphertext, so nothing to do
        checkVerifyReads("foo", "foo", "foo", "foo");           // both match, should stay the same
        checkVerifyReads("foo", "bar", "foo", null);            // ciphertext wrong, set to null
        checkVerifyReads(null, "foo", null, "foo");             // no plaintext, so nothing to do
    }

    private void checkVerifyReads(String plaintext, String encrypted, String expectedPlaintext, String expectedEncrypted) {
        EncryptionData data = createData(PLAINTEXT, plaintext, encrypted);
        MigrationProcessor processor = new MigrationProcessor(singletonList(data), encryptionService, batchEncryptionEnabled);
        processor.verifyDualWrites();
        validate(data, expectedPlaintext, expectedEncrypted);
    }

    @Test
    public void migrateInvalidDualWrites() {
        byte[] plaintext = "123".getBytes(UTF_8);
        Cryptotext invalidCryptotext = encryptionService.encrypt("456".getBytes(UTF_8), "emailKey", tenantOption);
        EncryptionData data = new EncryptionData(
                "dcl#1",
                DUAL_WRITE,
                "nameKey",
                plaintext,
                invalidCryptotext,
                null,
                tenantOption
        );
        List<EncryptionData> dataList = singletonList(data);
        MigrationProcessor processor = new MigrationProcessor(dataList, encryptionService, batchEncryptionEnabled);
        processor.verifyDualWrites();

        assertNull(data.getCryptotext());
        assertTrue(data.isModified());

        MigrationResult result = processor.migrate();
        assertNotNull(data.getCryptotext());
        assertNotEquals(data.getCryptotext(), invalidCryptotext);
        assertEquals(encryptionService.decrypt(data.getCryptotext()), plaintext);

        assertEquals(result.getTotal(), 1);
        assertEquals(result.getVerificationFailed(), 1);
        assertEquals(result.getModified(), 1);
        assertEquals(result.getEncrypted(), 1);
        assertEquals(result.getDecrypted(), 0);
        assertEquals(result.getRewrapped(), 0);
    }

    @Test
    public void migrate() {
        checkMigrate(PLAINTEXT, null, null, null, null);        // nothing to do
        checkMigrate(PLAINTEXT, "foo", null, "foo", null);      // already plaintext
        checkMigrate(PLAINTEXT, "foo", "foo", "foo", null);     // nuke ciphertext
        checkMigrate(PLAINTEXT, null, "foo", "foo", null);      // decrypt ciphertext then set it to null

        checkMigrate(DUAL_WRITE, null, null, null, null);       // nothing to do
        checkMigrate(DUAL_WRITE, "foo", null, "foo", "foo");    // encrypt
        checkMigrate(DUAL_WRITE, "foo", "foo", "foo", "foo");   // nothing to do
        checkMigrate(DUAL_WRITE, null, "foo", "foo", "foo");    // decrypt

        checkMigrate(ENCRYPT, null, null, null, null);          // nothing to do
        checkMigrate(ENCRYPT, "foo", null, null, "foo");        // encrypt, set plaintext to null
        checkMigrate(ENCRYPT, "foo", "foo", null, "foo");       // set plaintext to null
        checkMigrate(ENCRYPT, null, "foo", null, "foo");        // nothing to do
    }

    @Test
    public void rewrap() {
        testRewrap(ENCRYPT);
        testRewrap(DUAL_WRITE);
    }

    private void testRewrap(MigrationMode mode) {
        EncryptionData data = createData(mode, null, "foo");
        KmsKey kmsKey1 = data.getCryptotext().getKey();
        KeySupplierOption keySupplierOption = new KeySupplierOption(() -> wrap(() -> {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256);
            return generator.generateKey();
        }));
        encryptionService.rotateKey("nameKey", tenantOption, keySupplierOption);

        new MigrationProcessor(singletonList(data), encryptionService, batchEncryptionEnabled).migrate();
        KmsKey kmsKey2 = data.getCryptotext().getKey();
        assertNotEquals(kmsKey1, kmsKey2);
        assertEquals(kmsKey1.getVersion() + 1, kmsKey2.getVersion().intValue());
    }

    @Test
    public void rekey() {
        rekey(ENCRYPT);
        rekey(DUAL_WRITE);
    }

    private void rekey(MigrationMode mode) {
        EncryptionData data = new EncryptionData(
                "rekey#1",
                mode,
                "emailKey",
                null,
                encryptionService.encrypt("foo".getBytes(), "nameKey", tenantOption),
                null,
                tenantOption
        );
        KmsKey kmsKey1 = data.getCryptotext().getKey();
        assertEquals("emailKey", data.getVirtualKey());
        assertEquals("kmsNameKey", kmsKey1.getName());

        new MigrationProcessor(singletonList(data), encryptionService, batchEncryptionEnabled).migrate();

        KmsKey kmsKey2 = data.getCryptotext().getKey();
        assertNotEquals(kmsKey1, kmsKey2);
        assertEquals("emailKey", data.getVirtualKey());
        assertEquals("kmsEmailKey", kmsKey2.getName());
        assertEquals("kmsNameKey", kmsKey1.getName());

        assertEquals("foo".getBytes(), encryptionService.decrypt(data.getCryptotext()));
    }

    private void checkMigrate(MigrationMode mode, String plaintext, String encrypted, String expectedPlaintext, String expectedEncrypted) {
        EncryptionData data = createData(mode, plaintext, encrypted);
        new MigrationProcessor(singletonList(data), encryptionService, batchEncryptionEnabled).migrate();
        validate(data, expectedPlaintext, expectedEncrypted);
    }

    private EncryptionData createData(MigrationMode mode, String plaintext, String encrypted) {
        return new EncryptionData(
                "createData",
                mode,
                "nameKey",
                plaintext == null ? null : plaintext.getBytes(),
                encrypted == null ? null : encryptionService.encrypt(encrypted.getBytes(), "nameKey", tenantOption),
                null,
                tenantOption
        );
    }

    private void validate(EncryptionData data, String expectedPlaintext, String expectedEncrypted) {
        if (expectedPlaintext == null) {
            assertNull(data.getPlaintext());
        } else {
            assertEquals(expectedPlaintext, new String(data.getPlaintext(), UTF_8));
        }

        if (expectedEncrypted == null) {
            assertNull(data.getCryptotext());
        } else {
            assertEquals(expectedEncrypted, new String(encryptionService.decrypt(data.getCryptotext()), UTF_8));
        }
    }
}
