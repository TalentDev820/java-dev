package com.r.crypto.encryption.config;

import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.option.TenantOption;
import com.r.crypto.encryption.api.service.REncryptionService;
import com.r.crypto.encryption.hibernate.EntityEncryptionService;
import com.r.crypto.encryption.hibernate.test.TestPersistenceConfig;
import com.r.crypto.encryption.migration.MigrationMode;
import com.r.crypto.encryption.utils.LoggingTest;
import com.r.crypto.exception.RCryptoException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.orm.jpa.vendor.Database;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.testng.annotations.Ignore;
import org.testng.annotations.Test;

import java.io.InputStream;
import java.security.KeyStore;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

@Ignore
@ContextConfiguration(classes = {
        TestPersistenceConfig.class,
        EncryptionServiceConfigKeyStoreTest.Config.class
})
@TestPropertySource(properties = {
        "rnet.keystore.location=file",
        "rnet.keystore.password=foobar"
})
public class EncryptionServiceConfigKeyStoreTest extends LoggingTest {
    @Configuration
    public static class Config {
        @Autowired
        private Environment env;

        @Bean
        public Database getDatabase() {
            return Database.H2;
        }

        @Bean("encryptionKeyStore")
        @Qualifier("encryptionKeyStore")
        public KeyStore encryptionKeyStore() throws Exception {
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            InputStream inputStream = getClass().getClassLoader().getResourceAsStream("keystore.pkcs12");
            String password = env.getRequiredProperty("rnet.keystore.password");
            keystore.load(inputStream, password.toCharArray());
            return keystore;
        }
    }

    @Autowired
    private EntityEncryptionService entityEncryptionService;

    @Test
    public void encryptionServiceConfig() {
        REncryptionService encryptionService = entityEncryptionService.getEncryptionService();
        execute(() -> {
            assertEquals(entityEncryptionService.getDefaultMigrationMode(), MigrationMode.DUAL_WRITE);
            assertEquals(entityEncryptionService.getTenantMigrationModes().size(), 1);

            // Test that a fooKey has been created when no tenant is given
            byte[] plaintext = "foo".getBytes();
            Cryptotext cryptotext = encryptionService.encrypt(plaintext, "keystoreKey");
            assertNotNull(cryptotext);
            assertEquals(encryptionService.decrypt(cryptotext), plaintext);

            try {
                encryptionService.encrypt(plaintext, "keystoreKey", new TenantOption("tenant1"));
                fail("should not be able to encrypt with tenant because no tenants were configured");
            } catch (RCryptoException e) {
                // expected
            }
        });
    }
}
