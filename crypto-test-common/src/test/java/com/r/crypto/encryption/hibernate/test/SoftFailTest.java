package com.r.crypto.encryption.hibernate.test;

import static com.r.crypto.encryption.migration.MigrationMode.DISABLED;
import static com.r.crypto.encryption.migration.MigrationMode.DUAL_WRITE;
import static com.r.crypto.encryption.migration.MigrationMode.ENCRYPT;
import static com.r.crypto.encryption.migration.MigrationMode.PLAINTEXT;
import static com.r.crypto.encryption.utils.TestUtils.getTenant;
import static com.r.crypto.encryption.utils.TestUtils.verifyDbRow;
import static com.r.crypto.util.Util.findCause;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.fail;

import com.r.crypto.api.kms.ExportedKey;
import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.api.kms.SimpleKms;
import com.r.crypto.api.option.TenantOption;
import com.r.crypto.encryption.api.provider.EncryptionMetricsProvider;
import com.r.crypto.encryption.hibernate.EncryptedObject;
import com.r.crypto.encryption.hibernate.EncryptedString;
import com.r.crypto.encryption.hibernate.EntityEncryptionService;
import com.r.crypto.encryption.migration.MigrationMode;
import com.r.crypto.encryption.utils.LoggingTest;
import com.r.crypto.exception.RCryptoConsistencyException;
import com.r.crypto.exception.RCryptoException;
import com.r.crypto.exception.RCryptoMissingKeyException;
import com.r.crypto.provider.cipher.LocalKmsEncryptionProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.HashMap;
import java.util.Map;

@ContextConfiguration(classes = TestPersistenceConfig.class)
@TestPropertySource(properties = "vaultEnabled=false")
public class SoftFailTest extends LoggingTest {
    @Autowired
    @Qualifier("RCryptoDS")
    protected DataSource dataSource;

    @Autowired
    @Qualifier("RCryptoTM")
    private PlatformTransactionManager transactionManager;

    @Autowired
    protected PersonRepository personRepository;

    @Autowired
    protected EntityEncryptionService entityEncryptionService;

    @Autowired
    private EncryptionMetricsProvider encryptionMetricsProvider;

    private TransactionTemplate tx;

    private final KmsKey kmsNameKey = new KmsKey("kmsNameKey");
    private final TenantOption tenantOption = new TenantOption("tenant1");

    private LocalKmsEncryptionProvider localProvider;
    private SimpleKms kms;
    private MigrationMode originalMigrationMode;
    private Map<String, MigrationMode> originalTenantModes;
    private boolean originalSoftFailEnabled;
    private ExportedKey originalNameKey;

    @BeforeMethod
    public void beforeMethod() {
        execute(() -> {
            personRepository.deleteAllInBatch();
            originalMigrationMode = entityEncryptionService.getDefaultMigrationMode();
            originalTenantModes = new HashMap<>(entityEncryptionService.getTenantMigrationModes());
            originalSoftFailEnabled = entityEncryptionService.isSoftFailEnabled();
            tx = new TransactionTemplate(transactionManager);

            localProvider = (LocalKmsEncryptionProvider) encryptionMetricsProvider.getProvider();
            kms = (SimpleKms) localProvider.getKms();
            originalNameKey = kms.exportKey(kmsNameKey, tenantOption);
        });
    }

    @AfterMethod
    public void afterMethod() {
        execute(() -> {
            entityEncryptionService.setDefaultMigrationMode(originalMigrationMode);
            entityEncryptionService.setTenantMigrationModes(originalTenantModes);
            entityEncryptionService.setSoftFailEnabled(originalSoftFailEnabled);
        });
    }

    @Test
    public void encrypt_missingKey() {
        execute(() -> {
            // DISABLED or PLAINTEXT modes don't encrypt or decrypt, so no crypto failures possible
            testEncryption_missingKey(DISABLED,   true,  true);
            testEncryption_missingKey(DISABLED,   false, true);
            testEncryption_missingKey(PLAINTEXT,  true,  true);
            testEncryption_missingKey(PLAINTEXT,  false, true);

            // DUAL_WRITE succeeds only if softFail is enabled
            testEncryption_missingKey(DUAL_WRITE, true,  true);
            testEncryption_missingKey(DUAL_WRITE, false, false);

            // ENCRYPT cannot use plaintext, so crypto errors fail regardless of softFail
            testEncryption_missingKey(ENCRYPT,    true,  false);
            testEncryption_missingKey(ENCRYPT,    false, false);
        });
    }

    private void testEncryption_missingKey(MigrationMode mode, boolean enableSoftFail, boolean shouldSucceed) {
        try {
            // Encrypting name will fail if key is missing, but encrypting email should work
            kms.removeKey("kmsNameKey", tenantOption);
            PersonEntity person = new PersonEntity("John Doe", "john@gmail.com");
            testEncryption(person, mode, enableSoftFail, shouldSucceed ? null : RCryptoMissingKeyException.class);
        } finally {
            kms.addKey("kmsNameKey", originalNameKey.getKey(), tenantOption);
        }
    }

    /**
     * Soft fail isn't allowed if there's a tenant mismatch, because there's
     * no way to know which tenant is "correct", and we thus can't reliably
     * derive the migration mode. It is also a severe error that likely
     * indicates data corruption and it must be resolved immediately.
     */
    @Test
    public void encrypt_tenantMismatch() {
        execute(() -> {
            testEncryption_tenantMismatch(DISABLED,   true,  false);
            testEncryption_tenantMismatch(DISABLED,   false, false);

            testEncryption_tenantMismatch(PLAINTEXT,  true,  false);
            testEncryption_tenantMismatch(PLAINTEXT,  false, false);

            testEncryption_tenantMismatch(DUAL_WRITE, true,  false);
            testEncryption_tenantMismatch(DUAL_WRITE, false, false);

            testEncryption_tenantMismatch(ENCRYPT,    true,  false);
            testEncryption_tenantMismatch(ENCRYPT,    false, false);
        });
    }

    private void testEncryption_tenantMismatch(MigrationMode mode, boolean enableSoftFail, boolean shouldSucceed) {
        PersonEntity person = new PersonEntity("John Doe", "john@gmail.com");
        EncryptedString nameEnc = person.getNameEnc();
        nameEnc.setTenant("invalidtenant");
        testEncryption(person, mode, enableSoftFail, shouldSucceed ? null : RCryptoConsistencyException.class);
    }

    private void testEncryption(
            PersonEntity person,
            MigrationMode mode,
            boolean enableSoftFail,
            Class<? extends RCryptoException> expectedExceptionClass
    ) {
        entityEncryptionService.setDefaultMigrationMode(mode);
        entityEncryptionService.setSoftFailEnabled(enableSoftFail);

        if (expectedExceptionClass == null) {
            person = personRepository.save(person);
        } else {
            try {
                person = personRepository.save(person);
                fail("encrypt during db save should have failed");
            } catch (RCryptoException e) {
                assertNotNull(findCause(e, expectedExceptionClass));
                return;
            }
        }

        // Name cannot be encrypted because there was no key
        EncryptedString nameEnc = person.getNameEnc();
        assertEquals(nameEnc.getPlaintext(), "John Doe");
        assertNull(nameEnc.getCryptotext());
        verifyRow("John Doe", "NAME", person.getId(), PLAINTEXT, person);

        // Encrypted regardless of mode because there is no plaintext column mapping
        EncryptedObject<String> emailEnc = person.getEmailEnc();
        assertEquals(emailEnc.getPlaintext(), "john@gmail.com");
        assertNotNull(emailEnc.getCryptotext());
        verifyRow("john@gmail.com", "EMAIL", person.getId(), ENCRYPT, person);
    }

    @Test
    public void decrypt_missingKey() {
        execute(() -> {
            // No encryption happens when mode is DISABLED or PLAINTEXT, so no failures possible
            testDecryption_missingKey(DISABLED,   true,  true);
            testDecryption_missingKey(DISABLED,   false, true);
            testDecryption_missingKey(PLAINTEXT,  true,  true);
            testDecryption_missingKey(PLAINTEXT,  false, true);

            // DUAL_WRITE succeeds only if softFail is enabled
            testDecryption_missingKey(DUAL_WRITE, true,  true);
            testDecryption_missingKey(DUAL_WRITE, false, false);

            // ENCRYPT cannot use plaintext, so crypto errors fail regardless of softFail setting
            testDecryption_missingKey(ENCRYPT,    true,  false);
            testDecryption_missingKey(ENCRYPT,    false, false);
        });
    }

    private void testDecryption_missingKey(MigrationMode mode, boolean enableSoftFail, boolean shouldSucceed) {
        entityEncryptionService.setDefaultMigrationMode(mode);
        entityEncryptionService.setSoftFailEnabled(enableSoftFail);
        assertNotNull(kms.exportKey(kmsNameKey, tenantOption));

        PersonEntity person = personRepository.save(new PersonEntity("John Doe", "john@gmail.com"));

        // Remove the key so decrypt on db read fails
        kms.removeKey("kmsNameKey", tenantOption);
        try {
            testDecryption(shouldSucceed, person.getId(), RCryptoMissingKeyException.class);
        } finally {
            kms.addKey("kmsNameKey", originalNameKey.getKey(), tenantOption);
        }
    }

    /**
     * Soft fail isn't allowed if there's a tenant mismatch, because there's
     * no way to know which tenant is "correct", and we thus can't reliably
     * derive the migration mode. It is also a severe error that likely
     * indicates data corruption and it must be resolved immediately.
     */
    @Test
    public void decrypt_tenantMismatch() {
        execute(() -> {
            // Without cryptotext, we can't fail reading back the data; softFail doesn't matter
            testDecryption_tenantMismatch(DISABLED,   true,  true);
            testDecryption_tenantMismatch(DISABLED,   false, true);
            testDecryption_tenantMismatch(PLAINTEXT,  true,  true);
            testDecryption_tenantMismatch(PLAINTEXT,  false, true);

            // DUAL_WRITE succeeds only if softFail is enabled
            testDecryption_tenantMismatch(DUAL_WRITE, true,  false);
            testDecryption_tenantMismatch(DUAL_WRITE, false, false);

            // ENCRYPT cannot use plaintext, so crypto errors fail regardless of softFail setting
            testDecryption_tenantMismatch(ENCRYPT,    true,  false);
            testDecryption_tenantMismatch(ENCRYPT,    false, false);
        });
    }

    private void testDecryption_tenantMismatch(MigrationMode mode, boolean enableSoftFail, boolean shouldSucceed) {
        entityEncryptionService.setDefaultMigrationMode(mode);
        entityEncryptionService.setSoftFailEnabled(enableSoftFail);
        assertNotNull(kms.exportKey(kmsNameKey, tenantOption));

        // Save person in a different Hibernate transaction than anything
        // else; that will force our eventual db read to not use the cache,
        // which matters since we have to modify the db directly to "force"
        // this particular error during decrypt.
        Long id = tx.execute(status -> {
            PersonEntity person = new PersonEntity("John Doe", "john@gmail.com");
            person = personRepository.save(person);
            return person.getId();
        });

        if (mode.supportsCiphertext()) {
            String sql = "UPDATE PERSON"
                    + " SET NAME_ENC_HDR = '{aes:key=nameKey#1,tenant=invalidtenant}'"
                    + " WHERE ID = " + id;
            try (Connection connection = dataSource.getConnection()) {
                connection.setAutoCommit(false);
                try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                    assertEquals(stmt.executeUpdate(), 1);
                }
                connection.commit();
            } catch (Throwable t) {
                throw new RCryptoException(t);
            }
        }

        testDecryption(shouldSucceed, id, RCryptoConsistencyException.class);
    }

    private void testDecryption(
            boolean shouldSucceed,
            Long id,
            Class<? extends RCryptoException> expectedExceptionClass
    ) {
        if (shouldSucceed) {
            PersonEntity person = personRepository.findById(id).orElseThrow(NullPointerException::new);

            // Name cannot be encrypted because there was no key
            EncryptedString nameEnc = person.getNameEnc();
            assertEquals(nameEnc.getPlaintext(), "John Doe");
            assertNull(nameEnc.getCryptotext());
            assertNull(nameEnc.getEncryptedPlaintext());
            MigrationMode mode = entityEncryptionService.getTenantMigrationMode(person.getTenant());
            if (mode.supportsCiphertext()) {
                // Soft fail errors will erase the tenant; since we don't know
                // what exactly went wrong, we presume the tenant value may
                // have been incorrect.
                assertNull(nameEnc.getTenant());
            }

            // Encrypted regardless of mode because there is no plaintext column mapping
            EncryptedObject<String> emailEnc = person.getEmailEnc();
            assertEquals(emailEnc.getPlaintext(), "john@gmail.com");
            assertEquals(emailEnc.getEncryptedPlaintext(), "john@gmail.com");
            assertNotNull(emailEnc.getCryptotext());
            verifyRow("john@gmail.com", "EMAIL", person.getId(), ENCRYPT, person);
        } else {
            try {
                personRepository.findById(id).orElseThrow(NullPointerException::new);
                fail("decrypt during db fetch should have failed");
            } catch (RCryptoException e) {
                assertNotNull(findCause(e, expectedExceptionClass));
            }
        }
    }

    private void verifyRow(String expectedPlaintext, String column, long id, MigrationMode saveMode, PersonEntity personEntity) {
        try {
            assertEquals(verifyDbRow(
                            dataSource,
                            encryptionService,
                            "PERSON",
                            column,
                            expectedPlaintext,
                            saveMode,
                            getTenant(personEntity),
                            id,
                            false,
                            null),
                    1);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }
}
