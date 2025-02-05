package com.r.crypto.encryption.config;

import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.option.TenantOption;
import com.r.crypto.encryption.api.service.EncryptionService;
import com.r.crypto.encryption.hibernate.EntityEncryptionService;
import com.r.crypto.encryption.hibernate.test.TestPersistenceConfig;
import com.r.crypto.encryption.migration.MigrationMode;
import com.r.crypto.encryption.utils.LoggingTest;
import com.r.crypto.exception.RCryptoException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.testng.annotations.Test;

import static com.r.crypto.encryption.migration.MigrationMode.DISABLED;
import static java.util.Collections.singletonMap;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

@ContextConfiguration(classes = TestPersistenceConfig.class)
@TestPropertySource(properties = "vaultEnabled=false")
public class EncryptionServiceConfigTest extends LoggingTest {
    @Autowired
    private Environment env;

    @Autowired
    private EncryptionService encryptionService;

    @Autowired
    private EntityEncryptionService entityEncryptionService;

    @Test
    public void encryptionServiceConfig() {
        execute(() -> {
            MigrationMode mode = MigrationMode.valueOf(env.getProperty("rnet.encryption.defaultMode"));

            assertEquals(encryptionService, entityEncryptionService.getEncryptionService());
            assertEquals(entityEncryptionService.getEncryptionService(), encryptionService);
            assertEquals(entityEncryptionService.getDefaultMigrationMode(), mode);
            assertEquals(entityEncryptionService.getTenantMigrationModes(), singletonMap("disabledTenant", DISABLED));

            // Test that a nameKey has been created when no tenant is given
            byte[] plaintext = "foo".getBytes();
            Cryptotext cryptotext = encryptionService.encrypt(plaintext, "nameKey");
            assertNotNull(cryptotext);
            assertEquals(encryptionService.decrypt(cryptotext), plaintext);
            assertWrongTenantDecryptFails(cryptotext, "tenant1");
            assertWrongTenantDecryptFails(cryptotext, "tenant2");

            // Test that nameKey has been created for tenant1
            TenantOption tenant1 = new TenantOption("tenant1");
            Cryptotext cryptotextTenant1 = encryptionService.encrypt(plaintext, "nameKey", tenant1);
            assertNotNull(cryptotextTenant1);
            assertEquals(encryptionService.decrypt(cryptotextTenant1, tenant1), plaintext);
            assertWrongTenantDecryptFails(cryptotextTenant1, "tenant2");

            // Test that nameKey has been created for tenant2
            TenantOption tenant2 = new TenantOption("tenant2");
            Cryptotext cryptotextTenant2 = encryptionService.encrypt(plaintext, "nameKey", tenant2);
            assertNotNull(cryptotextTenant2);
            assertEquals(encryptionService.decrypt(cryptotextTenant2, tenant2), plaintext);
            assertWrongTenantDecryptFails(cryptotextTenant2, "tenant1");
        });
    }

    /**
     * Decrypting with the wrong tenant should fail because the wrong encryption
     * key is used, which causes the AES GCM tag validation to fail.
     */
    private void assertWrongTenantDecryptFails(Cryptotext cryptotext, String tenant) {
        try {
            if (tenant == null) {
                encryptionService.decrypt(cryptotext);
            } else {
                encryptionService.decrypt(cryptotext, new TenantOption(tenant));
            }
            fail("decrypt should fail with incorrect tenant");
        } catch (RCryptoException e) {
            // expected
        }
    }
}
