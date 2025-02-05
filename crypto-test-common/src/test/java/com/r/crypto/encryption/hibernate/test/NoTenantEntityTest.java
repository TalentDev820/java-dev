package com.r.crypto.encryption.hibernate.test;

import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.option.TenantOption;
import com.r.crypto.encryption.api.service.REncryptionService;
import com.r.crypto.encryption.hibernate.EncryptedObject;
import com.r.crypto.encryption.hibernate.EntityEncryptionService;
import com.r.crypto.encryption.migration.MigrationMode;
import com.r.crypto.encryption.utils.LoggingTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.sql.DataSource;
import java.util.List;

import static com.r.crypto.encryption.utils.TestUtils.getTenant;
import static com.r.crypto.encryption.utils.TestUtils.verifyDbRows;
import static com.r.crypto.util.Util.quote;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static java.util.Objects.requireNonNull;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

@ContextConfiguration(classes = TestPersistenceConfig.class)
@TestPropertySource(properties = "vaultEnabled=false")
public class NoTenantEntityTest extends LoggingTest {
    @Autowired
    private NoTenantRepository repository;

    @Autowired
    @Qualifier("RCryptoDS")
    private DataSource dataSource;

    @Autowired
    @Qualifier("RCryptoTM")
    private PlatformTransactionManager transactionManager;

    @Autowired
    private EntityEncryptionService entityEncryptionService;

    @Autowired
    private REncryptionService encryptionService;

    private TransactionTemplate tx;

    @BeforeMethod
    public void beforeMethod() {
        repository.deleteAllInBatch();
        tx = new TransactionTemplate(transactionManager);
    }

    @Test
    public void findPlaintextNames() {
        NoTenantEntity john = new NoTenantEntity();
        john.setName("john");
        NoTenantEntity paul = new NoTenantEntity();
        paul.setName("paul");

        System.out.println("before saveAll");
        repository.saveAll(asList(john, paul));
        List<String> plaintextNames = repository.findPlaintextNames();
        logger.info(plaintextNames.toString());
    }

    @Test
    public void findNames() {
        execute(() -> {
            NoTenantEntity john = new NoTenantEntity();
            john.setName("john");
            NoTenantEntity paul = new NoTenantEntity();
            paul.setName("paul");

            System.out.println("before saveAll");
            repository.saveAll(asList(john, paul));
            System.out.println("after saveAll");
            List<NoTenantEntity> findAll = repository.findAll();
            System.out.println("after findAll");
            List<EncryptedObject<String>> names = repository.findAllNames();
            names.forEach(entityEncryptionService::decrypt);

            logger.info("\n\nafter findAllNames\n");
            names.forEach(result -> logger.info(result.getPlaintext()));
            assertEquals(names.get(0).getPlaintext(), "john");
            assertEquals(names.get(1).getPlaintext(), "paul");

//            tx.executeWithoutResult(status -> repository.updateName(new EncryptedString(
//                    "fred",
//                    "smith",
//                    null,
//                    null,
//                    "com.r.crypto.encryption.hibernate.test.NoTenantEntity.nameEnc"
//            ), 1L));

            tx.executeWithoutResult(status -> repository.clearNames(asList(1L, 2L)));
            tx.executeWithoutResult(status -> repository.updateName("paulette", paul.getId()));

            tx.executeWithoutResult(status -> {
                assertEquals(repository.clearNames(singletonList(john.getId())), 1);
                logger.info("\n\nafter clearNames\n");
                repository.findAllNames().forEach(encryptedName -> logger.info(encryptedName.toString()));
                logger.info("\n\nafter findAllNames\n");
                assertNull(requireNonNull(repository.findById(john.getId()).orElse(null)).getName());
                assertEquals(requireNonNull(repository.findById(paul.getId()).orElse(null)).getName(), "paulette");
            });
        });
    }

    @Test
    public void listener() {
        execute(() -> {
            NoTenantEntity savedEntity = tx.execute(status -> {
                NoTenantEntity entity = new NoTenantEntity();
                entity.setName("raul");
                NoTenantEntity result = repository.save(entity);
                System.out.println("finished save: " + result);
                entity.setName("Acevedo");
                return result;
            });
            System.out.println("finished transaction: " + savedEntity);
//        printRows();
        });
    }

    private void printRows() {
        new JdbcTemplate(dataSource).queryForList("select * from no_tenant").forEach(row -> {
            Cryptotext nameEnc = Cryptotext.parse(
                    (String) row.get("NAME_ENC_HDR"),
                    (byte[]) row.get("NAME_ENC")
//                    DatatypeConverter.parseHexBinary((String) row.get("NAME_ENC"))
            );
            TenantOption tenantOption = TenantOption.valueOf((String) row.get("TENANT"));
            byte[] name = encryptionService.decrypt(nameEnc, tenantOption);

            Cryptotext jsonEnc = Cryptotext.parse(
                    (String) row.get("JSON_ENC_HDR"),
                    (byte[]) row.get("JSON_ENC")
            );
            byte[] json = encryptionService.decrypt(jsonEnc, tenantOption);

            logger.info("\n\nrow: " + row
                            + "\n     name: " + String.format("%-15s", quote(toString(name))) + " " + nameEnc
//                    + "\n     json: " + String.format("%-15s", quote(toString(json))) + " " + jsonEnc
                            + "\n"
            );
        });
    }

    private static String toString(byte[] bytes) {
        return bytes == null ? null : new String(bytes);
    }

    @Test
    public void save() {
        execute(() -> {
            NoTenantEntity entity = new NoTenantEntity();
            entity.setName("Inigo Montoya");
            logger.info("\n\nentering save\n");
            NoTenantEntity savedEntity = repository.save(entity);
            logger.info("\n\nfinished save\n");
            assertEquals(entity, savedEntity);
            MigrationMode saveMode = entityEncryptionService.getDefaultMigrationMode();
            verifyDbRows(dataSource, encryptionService, "NO_TENANT", "NAME", "Inigo Montoya", saveMode, getTenant(entity), false, null);

            NoTenantEntity fetchedEntity = repository.findById(savedEntity.getId()).orElse(null);
            assertNotNull(fetchedEntity);
            assertEquals(savedEntity.getId(), fetchedEntity.getId());
            assertEquals(savedEntity.getName(), fetchedEntity.getName());
        });
    }
}
