package com.r.crypto.encryption.hibernate.test;

import com.r.crypto.encryption.utils.LoggingTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.test.context.ContextConfiguration;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.sql.DataSource;

import static com.r.crypto.encryption.utils.TestUtils.verifyNonEncryptedDbRows;
import static org.testng.Assert.assertEquals;

@ContextConfiguration(classes = TestPersistenceConfig.class)
public class NoEncryptionEntityTest extends LoggingTest {
    @Autowired
    private NoEncryptionTestRepository noEncryptionTestRepository;

    @Autowired
    @Qualifier("RCryptoDS")
    private DataSource dataSource;

    @BeforeMethod
    public void beforeMethod() {
        execute(() -> noEncryptionTestRepository.deleteAllInBatch());
    }

    @Test
    public void save() {
        execute(() -> {
            NoEncryptionEntity entity = new NoEncryptionEntity();
            entity.setName("foo");
            NoEncryptionEntity savedEntity = noEncryptionTestRepository.save(entity);
            assertEquals(entity, savedEntity);
            verifyNonEncryptedDbRows(dataSource, "NAME", "NO_ENCRYPTION", savedEntity.getName());
        });
    }
}
