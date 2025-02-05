package com.r.crypto.encryption.hibernate.test;

import com.r.crypto.encryption.api.service.REncryptionService;
import com.r.crypto.encryption.hibernate.DebugInterceptor;
import com.r.crypto.encryption.hibernate.EntityEncryptionService;
import com.r.crypto.encryption.migration.MigrationMode;
import com.r.crypto.encryption.utils.LoggingTest;
import org.hibernate.Session;
import org.hibernate.Transaction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.test.context.ContextConfiguration;
import org.testng.annotations.Test;

import jakarta.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import java.util.List;
import java.util.Optional;

import static com.r.crypto.encryption.migration.MigrationMode.DISABLED;
import static com.r.crypto.encryption.migration.MigrationMode.DUAL_WRITE;
import static com.r.crypto.encryption.migration.MigrationMode.ENCRYPT;
import static com.r.crypto.encryption.migration.MigrationMode.PLAINTEXT;
import static com.r.crypto.encryption.utils.TestUtils.assertSqlCalls;
import static com.r.crypto.encryption.utils.TestUtils.getTenant;
import static com.r.crypto.encryption.utils.TestUtils.verifyDbRows;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

@ContextConfiguration(classes = TestPersistenceConfig.class)
public class HibernateTest extends LoggingTest {
    @Autowired
    private PersonRepository personRepository;

    @Autowired
    private REncryptionService encryptionService;

    @Autowired
    private EntityEncryptionService entityEncryptionService;

    @Autowired
    @Qualifier("RCryptoDS")
    private DataSource dataSource;

    @Autowired
    @Qualifier("RCryptoEMF")
    private EntityManagerFactory entityManagerFactory;

    @Test
    public void persist() throws Exception {
        testPersist(DISABLED);
        testPersist(PLAINTEXT);
        testPersist(DUAL_WRITE);
        testPersist(ENCRYPT);
    }

    private void testPersist(MigrationMode mode) throws Exception {
        MigrationMode originalMode = entityEncryptionService.getDefaultMigrationMode();
        entityEncryptionService.setDefaultMigrationMode(mode);
        try {
            System.out.println("entering persist test mode=" + mode);
            String name = "persistName";
            PersonEntity person = new PersonEntity(name);

            DebugInterceptor.reset();
            try (Session session = entityManagerFactory.createEntityManager().unwrap(Session.class)) {
                Transaction tx = session.beginTransaction();
                session.persist(person);
                tx.commit();
                System.out.println("persisted person");
            }
            assertSqlCalls(1, 0, 0, 0);
            assertEquals(person.getName(), name);
            assertEquals(person.getVersion().shortValue(), 0);

            verify(name, person);
            List<PersonEntity> people = personRepository.findAll();
            assertEquals(people.size(), 1);
            assertEquals(people.get(0).getName(), name);
            assertSqlCalls(1, 0, 1, 0);
            System.out.println("finished persist test mode=" + mode);
        } finally {
            entityEncryptionService.setDefaultMigrationMode(originalMode);
            personRepository.deleteAllInBatch();
        }
    }

    @Test
    public void save() throws Exception {
        testSave(DISABLED);
        testSave(PLAINTEXT);
        testSave(DUAL_WRITE);
        testSave(ENCRYPT);
    }

    private void testSave(MigrationMode mode) throws Exception {
        MigrationMode originalMode = entityEncryptionService.getDefaultMigrationMode();
        entityEncryptionService.setDefaultMigrationMode(mode);
        try {
            System.out.println("entering save test mode=" + mode);
            String name = "saveName";
            PersonEntity person = new PersonEntity(name);

            final Long id;
            DebugInterceptor.reset();
            try (Session session = entityManagerFactory.createEntityManager().unwrap(Session.class)) {
                Transaction tx = session.beginTransaction();
                id = (Long) session.save(person);
                tx.commit();
                System.out.println("saved person");
            }
            assertSqlCalls(1, 0, 0, 0);
            assertEquals(person.getName(), name);
            assertEquals(person.getVersion().shortValue(), 0);

            verify(name, person);
            Optional<PersonEntity> result = personRepository.findById(id);
            assertSqlCalls(1, 0, 1, 0);
            assertTrue(result.isPresent());
            assertEquals(result.get().getName(), name);
            assertEquals(person.getVersion().shortValue(), 0);
            System.out.println("finished save test mode=" + mode);
        } finally {
            entityEncryptionService.setDefaultMigrationMode(originalMode);
            personRepository.deleteAllInBatch();
        }
    }

    @Test
    public void saveOrUpdate() throws Exception {
        testSaveOrUpdate(DISABLED);
        testSaveOrUpdate(PLAINTEXT);
        testSaveOrUpdate(DUAL_WRITE);
        testSaveOrUpdate(ENCRYPT);
    }

    private void testSaveOrUpdate(MigrationMode mode) throws Exception {
        MigrationMode originalMode = entityEncryptionService.getDefaultMigrationMode();
        entityEncryptionService.setDefaultMigrationMode(mode);
        try {
            System.out.println("entering saveOrUpdate test mode=" + mode);
            String name = "saveOrUpdateName";
            PersonEntity person = new PersonEntity(name);

            DebugInterceptor.reset();
            try (Session session = entityManagerFactory.createEntityManager().unwrap(Session.class)) {
                Transaction tx = session.beginTransaction();
                session.saveOrUpdate(person);
                tx.commit();
                System.out.println("saved person");
            }
            assertSqlCalls(1, 0, 0, 0);
            assertEquals(person.getName(), name);
            assertEquals(person.getVersion().shortValue(), 0);

            verify(name, person);
            List<PersonEntity> people = personRepository.findAll();
            assertSqlCalls(1, 0, 1, 0);
            assertEquals(people.size(), 1);
            assertEquals(people.get(0).getName(), name);
            assertEquals(person.getVersion().shortValue(), 0);
            System.out.println("finished saveOrUpdate test mode=" + mode);
        } finally {
            entityEncryptionService.setDefaultMigrationMode(originalMode);
            personRepository.deleteAllInBatch();
        }
    }

    @Test
    public void update() throws Exception {
        testUpdate(DISABLED);
        testUpdate(PLAINTEXT);
        testUpdate(DUAL_WRITE);
        testUpdate(ENCRYPT);
    }

    private void testUpdate(MigrationMode mode) throws Exception {
        MigrationMode originalMode = entityEncryptionService.getDefaultMigrationMode();
        entityEncryptionService.setDefaultMigrationMode(mode);
        try {
            System.out.println("entering update test mode=" + mode);
            String name = "updateName1";
            PersonEntity person = new PersonEntity(name);

            DebugInterceptor.reset();
            try (Session session = entityManagerFactory.createEntityManager().unwrap(Session.class)) {
                Transaction tx = session.beginTransaction();
                session.save(person);
                tx.commit();
                System.out.println("saved initial person");
            }
            assertSqlCalls(1, 0, 0, 0);
            assertEquals(person.getName(), name);
            assertEquals(person.getVersion().shortValue(), 0);

            name = "updateName2";
            try (Session session = entityManagerFactory.createEntityManager().unwrap(Session.class)) {
                Transaction tx = session.beginTransaction();
                person.setName(name);
                session.update(person);
                tx.commit();
                System.out.println("updated name");
            }
            assertEquals(person.getName(), name);

            verify(name, person);
            List<PersonEntity> people = personRepository.findAll();
            assertSqlCalls(1, 1, 1, 0);
            assertEquals(people.size(), 1);
            assertEquals(people.get(0).getName(), name);
            assertEquals(person.getVersion().shortValue(), 1);
            System.out.println("finished update test mode=" + mode);
        } finally {
            entityEncryptionService.setDefaultMigrationMode(originalMode);
            personRepository.deleteAllInBatch();
        }
    }

    @Test
    public void merge() {
        testMerge(DISABLED);
        testMerge(PLAINTEXT);
        testMerge(DUAL_WRITE);
        testMerge(ENCRYPT);
    }

    private void testMerge(MigrationMode mode) {
        MigrationMode originalMode = entityEncryptionService.getDefaultMigrationMode();
        entityEncryptionService.setDefaultMigrationMode(mode);
        try {
            System.out.println("entering merge test mode=" + mode);
            String name = "mergeName";
            PersonEntity person = new PersonEntity(name);

            final PersonEntity mergedPerson;
            DebugInterceptor.reset();
            try (Session session = entityManagerFactory.createEntityManager().unwrap(Session.class)) {
                Transaction tx = session.beginTransaction();
                session.save(person);
                tx.commit();
                System.out.println("saved initial person");
                assertSqlCalls(1, 0, 0, 0);

                session.evict(person);
                tx = session.beginTransaction();
                name = "postMergeName";
                person.setName(name);
                mergedPerson = (PersonEntity) session.merge(person);
                tx.commit();
                System.out.println("merged second person");
            }
            assertSqlCalls(1, 1, 1, 0);
            assertEquals(person.getName(), name);
            assertEquals(mergedPerson.getName(), name);
            System.out.println("finished merge test mode=" + mode);
        } finally {
            entityEncryptionService.setDefaultMigrationMode(originalMode);
            personRepository.deleteAllInBatch();
        }
    }

    private void verify(String expectedPlaintext, PersonEntity person) throws Exception {
        int modifiedRows = verifyDbRows(
                dataSource,
                encryptionService,
                "PERSON",
                "NAME",
                expectedPlaintext,
                entityEncryptionService.getDefaultMigrationMode(),
                getTenant(person),
                true,
                entityEncryptionService.getEncryptionJobId()
        );
        assertEquals(modifiedRows, 1);
    }
}
