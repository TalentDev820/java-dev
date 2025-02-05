package com.r.crypto.encryption.hibernate.test;

import static com.r.crypto.encryption.hibernate.EncryptedEntityListener.withPassthrough;
import static com.r.crypto.encryption.hibernate.EntityCrawler.CASCADE_ANY;
import static com.r.crypto.encryption.hibernate.EntityCrawler.CASCADE_SAVE;
import static com.r.crypto.encryption.hibernate.EntityEncryptionService.IGNORE_ENCRYPTION_JOB_ID;
import static com.r.crypto.encryption.hibernate.test.JsonNodeToBytesConverter.mapper;
import static com.r.crypto.encryption.migration.MigrationMode.DISABLED;
import static com.r.crypto.encryption.migration.MigrationMode.DUAL_WRITE;
import static com.r.crypto.encryption.migration.MigrationMode.ENCRYPT;
import static com.r.crypto.encryption.migration.MigrationMode.PLAINTEXT;
import static com.r.crypto.encryption.utils.TestUtils.assertSqlCalls;
import static com.r.crypto.encryption.utils.TestUtils.getTenant;
import static com.r.crypto.encryption.utils.TestUtils.verifyDbRow;
import static com.r.crypto.encryption.utils.TestUtils.verifyDbRows;
import static com.r.crypto.util.ExceptionWrapper.wrap;
import static com.r.crypto.util.Util.list;
import static com.r.crypto.util.Util.quote;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static java.util.Objects.requireNonNull;
import static org.slf4j.event.Level.INFO;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNotSame;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.r.crypto.api.option.TenantOption;
import com.r.crypto.encryption.hibernate.DebugInterceptor;
import com.r.crypto.encryption.hibernate.EncryptedEntityCache;
import com.r.crypto.encryption.hibernate.EntityEncryptionService;
import com.r.crypto.encryption.jobs.EncryptedTableProcessor;
import com.r.crypto.encryption.jobs.EncryptedTableProcessor.ProcessorResult;
import com.r.crypto.encryption.migration.MigrationMode;
import com.r.crypto.encryption.utils.LoggingTest;
import org.hibernate.Cache;
import org.hibernate.Hibernate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Lazy;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.PersistenceContext;
import javax.sql.DataSource;
import java.sql.JDBCType;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

@ContextConfiguration(classes = { TestPersistenceConfig.class, TestMetricsConfig.class })
public class PersonTest extends LoggingTest {
    private static final String PERSON_TABLE = "PERSON";
    private static final String COMPANY_TABLE = "COMPANY";

    public static final String NAME_COLUMN = "NAME";
    public static final String EMAIL_COLUMN = "EMAIL";
    public static final String JSON_COLUMN = "JSON";

    @Autowired
    @Qualifier("RCryptoDS")
    protected DataSource dataSource;

    @PersistenceContext(unitName = "RCryptoEMF")
    private EntityManager entityManager;

    @Autowired
    @Qualifier("RCryptoEMF")
    protected EntityManagerFactory entityManagerFactory;

    @Autowired
    @Qualifier("RCryptoTM")
    protected PlatformTransactionManager transactionManager;

    @Autowired
    protected PersonRepository personRepository;

    @Autowired
    protected CompanyRepository companyRepository;

    @Autowired
    protected EntityEncryptionService entityEncryptionService;

    @Lazy
    @Autowired
    private EncryptedEntityCache entityCache;

    @Autowired
    private TestEncryptionMetricsService metricsService;

    protected TransactionTemplate tx;
    protected JdbcTemplate jdbcTemplate;
    protected final JsonNodeToBytesConverter jsonConverter = new JsonNodeToBytesConverter();
    private MigrationMode originalMigrationMode;
    private Map<String, MigrationMode> originalTenantModes;

    @BeforeMethod
    public void beforeMethod() {
        execute(() -> wrap(() -> {
            personRepository.deleteAllInBatch();
            companyRepository.deleteAllInBatch();
            tx = new TransactionTemplate(transactionManager);
            jdbcTemplate = new JdbcTemplate(dataSource);
            originalMigrationMode = entityEncryptionService.getDefaultMigrationMode();
            originalTenantModes = new HashMap<>(entityEncryptionService.getTenantMigrationModes());
        }));
    }

    @AfterMethod
    public void afterMethod() {
        execute(() -> {
            entityEncryptionService.setDefaultMigrationMode(originalMigrationMode);
            entityEncryptionService.setTenantMigrationModes(originalTenantModes);
        });
    }

    /** This isn't a test, it's for debugging CI jobs to see what SQL types are in a table */
    @Test
    public void dumpMetadata() {
        execute(() -> {
            ResultSet rs = dataSource.getConnection().prepareStatement("select * from person").executeQuery();
            ResultSetMetaData metadata = rs.getMetaData();
            for (int i = 1; i <= metadata.getColumnCount(); i++) {
                logger.info(String.format("  column %2d: table=%10s column=%-16s type=%5s jdbcType=%-10s typeName=%-10s class=%s",
                        i,
                        metadata.getTableName(i),
                        metadata.getColumnName(i),
                        metadata.getColumnType(i),
                        JDBCType.valueOf(metadata.getColumnType(i)),
                        metadata.getColumnTypeName(i),
                        metadata.getColumnClassName(i)
                ));
            }
        });
    }

    @Test
    public void nullField() {
        execute(() -> {
            PersonEntity personEntity = new PersonEntity(null, "mysterious1@gmail.com");
            PersonEntity savedEntity = personRepository.save(personEntity);
            assertEquals(personEntity.getEmail(), savedEntity.getEmail());
            assertNull(savedEntity.getJson());
            verify(personEntity.getEmail(), EMAIL_COLUMN, ENCRYPT, savedEntity);
            verify(null, JSON_COLUMN, entityEncryptionService.getTenantMigrationMode(personEntity.getTenant()), savedEntity);
        });
    }

    /**
     * Test encryption enabled for a tenant that's different from the tenant
     * the test is using, and no default has been specified (which causes
     * unrecognized tenants to default to DISABLED).
     */
    @Test
    public void encryptionDisabled_mixedTenants() {
        execute(() -> {
            entityEncryptionService.setTenantMigrationModes(singletonMap("tenant1", DUAL_WRITE));
            testPerson(DISABLED);
            companiesTest();
            assertMetrics(62);
        });
    }

    @Test
    public void combinationTest_Disabled() {
        execute(() -> {
            testPerson(DISABLED);
            companiesTest();
            assertMetrics(17);
        });
    }

    @Test
    public void combinationTest_Plaintext() {
        execute(() -> {
            testPerson(PLAINTEXT);
            companiesTest();
            assertMetrics(17);
        });
    }

    @Test
    public void combinationTest_DualWrite() {
        execute(() -> {
            testPerson(DUAL_WRITE);
            companiesTest();
            assertMetrics(62);
        });
    }

    @Test
    public void combinationTest_Encrypt() {
        execute(() -> {
            testPerson(ENCRYPT);
            companiesTest();
            assertMetrics(76);
        });
    }

    @Test
    public void saveUpdate_DisabledToPlaintext() {
        execute(() -> saveUpdateDifferentMode(DISABLED, PLAINTEXT));
    }

    @Test
    public void saveUpdate_DisabledToDualWrite() {
        execute(() -> saveUpdateDifferentMode(DISABLED, DUAL_WRITE));
    }

    @Test
    public void saveUpdate_DisabledToEncrypt() {
        execute(() -> saveUpdateDifferentMode(DISABLED, ENCRYPT));
    }

    @Test
    public void saveUpdate_DisabledToDisabled() {
        execute(() -> saveUpdateDifferentMode(DISABLED, DISABLED));
    }

    @Test
    public void saveUpdate_PlaintextToDisabled() {
        execute(() -> saveUpdateDifferentMode(PLAINTEXT, DISABLED));
    }

    @Test
    public void saveUpdate_PlaintextToDualWrite() {
        execute(() -> saveUpdateDifferentMode(PLAINTEXT, DUAL_WRITE));
    }

    @Test
    public void saveUpdate_PlaintextToEncrypt() {
        execute(() -> saveUpdateDifferentMode(PLAINTEXT, ENCRYPT));
    }

    @Test
    public void saveUpdate_PlaintextToPlaintext() {
        execute(() -> saveUpdateDifferentMode(PLAINTEXT, PLAINTEXT));
    }

    @Test
    public void saveUpdate_DualWriteToDisabled() {
        execute(() -> saveUpdateDifferentMode(DUAL_WRITE, DISABLED));
    }

    @Test
    public void saveUpdate_DualWriteToPlaintext() {
        execute(() -> saveUpdateDifferentMode(DUAL_WRITE, PLAINTEXT));
    }

    @Test
    public void saveUpdate_DualWriteToEncrypt() {
        execute(() -> saveUpdateDifferentMode(DUAL_WRITE, ENCRYPT));
    }

    @Test
    public void saveUpdate_DualWriteToDualWrite() {
        execute(() -> saveUpdateDifferentMode(DUAL_WRITE, DUAL_WRITE));
    }

    @Test
    public void saveUpdate_EncryptToDisabled() {
        execute(() -> saveUpdateDifferentMode(ENCRYPT, DISABLED));
    }

    @Test
    public void saveUpdate_EncryptToPlaintext() {
        execute(() -> saveUpdateDifferentMode(ENCRYPT, PLAINTEXT));
    }

    @Test
    public void saveUpdate_EncryptToDualWrite() {
        execute(() -> saveUpdateDifferentMode(ENCRYPT, DUAL_WRITE));
    }

    @Test
    public void saveUpdate_EncryptToEncrypt() {
        execute(() -> saveUpdateDifferentMode(ENCRYPT, ENCRYPT));
    }

    /** Fetch then save without modifying data should not result in SQL update */
    private void saveUpdateDifferentMode(MigrationMode saveMode, MigrationMode updateMode) {
        // Question: Why don't we pass clear=true and flush=false?
        //
        // Answer: EntityManager.clear only detaches managed entities; without
        // a prior flush, the EntityManager may lose updates seemingly committed,
        // and the next SQL read could return an old version of the object.
        executeSaveUpdateTest(saveMode, updateMode, false, false);
        executeSaveUpdateTest(saveMode, updateMode, false, true);
        executeSaveUpdateTest(saveMode, updateMode, true, true);
    }

    private void executeSaveUpdateTest(
            MigrationMode saveMode,
            MigrationMode updateMode,
            boolean entityManagerClear,
            boolean entityManagerFlush) {
        System.out.println("saveUpdateDifferentMode " + saveMode + " to " + updateMode
                + " clear=" + entityManagerClear
                + " flush=" + entityManagerFlush);

        // Save the initial entity
        String name = "name1", email = "email1@gmail.com", json = quote("json1");
        PersonEntity person = saveUpdate(
                "save initial person",
                saveMode,
                name, email, json,
                0,          // new row version is always 0
                1, 0, 0,    // single insert; new entity so no queries
                entityManagerClear, entityManagerFlush,
                () -> personRepository.save(new PersonEntity("name1", "email1@gmail.com", json))
        );

        // Fetch and save without any changes shouldn't do a DB update
        saveUpdate(
                "no-op save",
                saveMode,
                name, email, json,
                0,          // same initial row version
                0, 0, 1,    // no updates, only the getOne query
                entityManagerClear, entityManagerFlush,
                () -> personRepository.save(personRepository.getOne(person.getId()))
        );

        // We change the name only, but all the EncryptedObjects will be
        // persisted using the updateMode.
        name = "name2";
        saveUpdate(
                "first update",
                updateMode,
                name, email, json,
                1,          // row updated to new version
                0, 1, 1,    // single update and getOne query
                entityManagerClear, entityManagerFlush,
                () -> {
                    PersonEntity p = personRepository.getOne(person.getId());
                    p.setName("name2");
                    return p; // JPA will perform an implicit save()
                }
        );

        // Replacing plaintext with itself (or a copy) shouldn't cause an update
        String nameForLambda = name;
        saveUpdate(
                "unmodified save after update",
                updateMode,
                name, email, json,
                1,          // no updates so row version the same
                0, 0, 1,    // just the getOne query
                entityManagerClear, entityManagerFlush,
                () -> {
                    PersonEntity p = personRepository.getOne(person.getId());
                    // Calls to updatePlaintext will nuke encryptedPlaintext/plaintext,
                    // but EncryptedType.equals should determine no db update needed
                    p.setName(nameForLambda);
                    p.setEmail(email);
                    p.setJson(wrap(() -> new ObjectMapper().readTree(json)));
                    return personRepository.save(p);
                }
        );

        tx.executeWithoutResult(status -> {
            personRepository.deleteAll();
            companyRepository.deleteAll();
            entityManager.flush();
            entityManager.clear();
        });

        System.out.println("completed saveUpdateDifferentMode " + saveMode + " to " + updateMode
                + " clear=" + entityManagerClear
                + " flush=" + entityManagerFlush);
    }

    private PersonEntity saveUpdate(
            String message,
            MigrationMode mode,
            String name,
            String email,
            String json,
            int rowVersion,
            int inserts,
            int updates,
            int selects,
            boolean entityManagerClear,
            boolean entityManagerFlush,
            Supplier<PersonEntity> supplier
    ) {
        System.out.println(message + ": starting");

        DebugInterceptor.reset();
        entityEncryptionService.setDefaultMigrationMode(mode);
        PersonEntity person = requireNonNull(tx.execute(status -> {
            PersonEntity p = supplier.get();
            if (entityManagerFlush) {
                System.out.println(message + ": em.flush");
                entityManager.flush();
            }
            return p;
        }));
        System.out.println(message + ": exited tx.execute");

        if (entityManagerClear) {
            System.out.println(message + ": em.clear");
            entityManager.clear();
        }
        System.out.println(message + ": complete");

        assertEquals(person.getVersion().shortValue(), rowVersion);
        assertSqlCalls(inserts, updates, selects, 0);
        verifyPerson(person, mode, name, email, json);
        assertPersonJobNoCryptoUpdates(singletonList(person.getId()));
        assertSqlCalls(inserts, updates, selects + 1, 0);
        System.out.println(message + ": complete");

        return person;
    }

    private void testPerson(MigrationMode defaultMigrationMode) {
        entityEncryptionService.setDefaultMigrationMode(defaultMigrationMode);
        MigrationMode saveMode = entityEncryptionService.getTenantMigrationMode("tenant1");

        wrap(() -> {
            CompanyEntity r = createCompany("r");
            CompanyEntity moneygram = createCompany("moneygram");
            PersonEntity personEntity = requireNonNull(tx.execute(status -> {
                JsonNode jsonNode = jsonConverter.convertToEntityAttribute("[1,2,3]".getBytes());
                jsonConverter.convertToDatabaseColumn(jsonNode);
                PersonEntity person = new PersonEntity("one@gmail.com", jsonNode);
                assertNull(person.getEncryptionJobId());
                ((ArrayNode) person.getJson()).add(4);
                person.setCompany(r);
                person.setPreviousCompany(moneygram);
                person.setCompanies(list(r, moneygram));
                System.out.println("saving person: " + person);
                personRepository.save(person);
                System.out.println("person saved: " + person);
                ((ArrayNode) person.getJson()).add(5);
                return person;
            }));

            System.out.println("after execute");
            long rId = r.getId();
            long moneygramId = moneygram.getId();
            PersonEntity fetchedEntity = personRepository.getOne(personEntity.getId());
            System.out.println("validating fetchedEntity=" + fetchedEntity);
            assertNotSame(personEntity, fetchedEntity);
            assertEquals(fetchedEntity.getEncryptionJobId(), "hi");
            verifyPerson(fetchedEntity, saveMode, null, "one@gmail.com", "[1,2,3,4,5]");
            assertEquals(fetchedEntity.getCompany().getName(), "r");
            assertEquals(fetchedEntity.getPreviousCompany().getName(), "moneygram");
            verifyRow(personEntity.getCompany().getName(), COMPANY_TABLE, NAME_COLUMN, rId, saveMode, fetchedEntity);
            verifyRow(personEntity.getPreviousCompany().getName(), COMPANY_TABLE, NAME_COLUMN, moneygramId, saveMode, fetchedEntity);
            System.out.println("validated fetchedEntity");

            PersonEntity copy = new PersonEntity();
            copy.setId(fetchedEntity.getId());
            copy.setVersion(fetchedEntity.getVersion());
            copy.setLastModifiedDate(fetchedEntity.getLastModifiedDate());
            copy.setTenant(fetchedEntity.getTenant());
            copy.setJson(mapper.readTree("[1,2,3]"));
            copy.setEmail("copy@gmail.com");
            copy.setName("Copy Name");
            copy.setCompany(r);
            copy.setPreviousCompany(moneygram);
            System.out.println("saving copy=" + copy);
            PersonEntity secondFetch = personRepository.save(copy);
            System.out.println("validating copy=" + copy);
            verifyPerson(secondFetch, saveMode, "Copy Name", "copy@gmail.com", "[1,2,3]");
            assertEquals(secondFetch.getCompany().getName(), "r");
            assertEquals(secondFetch.getPreviousCompany().getName(), "moneygram");
            verifyRow("r", COMPANY_TABLE, NAME_COLUMN, rId, saveMode, fetchedEntity);
            verifyRow("moneygram", COMPANY_TABLE, NAME_COLUMN, moneygramId, saveMode, fetchedEntity);
            System.out.println("copy validated");

            System.out.println("bad equals block starting");
            // secondFetch.setName(null);
            // secondFetch.setEmail("foo@bar.com");
            ((ArrayNode) secondFetch.getJson()).add(4);
            personRepository.save(secondFetch); // bad equals combinationTest_Encrypt
            System.out.println("bad equals block secondFetch saved");
            PersonEntity thirdPerson = personRepository.findById(personEntity.getId()).get();
            // assertNull(thirdPerson.getName());
            System.out.println("bad equals block thirdPerson fetched");
            // assertEquals(thirdPerson.getEmail(), "foo@bar.com");
            assertEquals(thirdPerson.getJson().toString(), "[1,2,3,4]");
            assertEquals(thirdPerson.getCompany().getName(), "r");
            assertEquals(thirdPerson.getPreviousCompany().getName(), "moneygram");
            // verify("foo@bar.com", EMAIL_COLUMN, ENCRYPT, thirdPerson);
            // verify(null, NAME_COLUMN, saveMode, thirdPerson);
            verify("[1,2,3,4]", JSON_COLUMN, saveMode, thirdPerson);
            verifyRow("r", COMPANY_TABLE, NAME_COLUMN, rId, saveMode, fetchedEntity);
            verifyRow("moneygram", COMPANY_TABLE, NAME_COLUMN, moneygramId, saveMode, fetchedEntity);
        });
    }

    private void assertMetrics(int expectedMetricsCount) {
        logger.info("metrics recorded " + metricsService.getEvents().size() + " events");
        assertEquals(metricsService.getEvents().size(), expectedMetricsCount);
        metricsService.clear();
    }

    private void companiesTest() {
        System.out.println("starting companiesTest");
        TransactionStatus writeTxStatus = transactionManager.getTransaction(new DefaultTransactionDefinition());

        CompanyEntity bankOfAmerica = createCompany("Bank of America");
        CompanyEntity chase = createCompany("Chase");
        CompanyEntity citibank = createCompany("Citibank");
        CompanyEntity wellsFargo = createCompany("Wells Fargo");

        PersonEntity alice = createPerson("alice");
        PersonEntity bob = createPerson("bob");
        PersonEntity cindy = createPerson("cindy");
        PersonEntity dave = createPerson("dave");

        alice.getCompanies().add(bankOfAmerica);
        alice.getCompanies().add(chase);
        bob.getCompanies().add(bankOfAmerica);
        cindy.getCompanies().add(chase);
        cindy.getCompanies().add(wellsFargo);
        dave.getCompanies().add(bankOfAmerica);
        dave.getCompanies().add(citibank);
        dave.getCompanies().add(wellsFargo);
        save(bankOfAmerica, chase, citibank, wellsFargo);

        final PersonEntity a = alice, b = bob, c = cindy, d = dave;
        System.out.println("encrypt and save companies and people");
        timer.bracketTime(INFO, "encryptAndSave", () -> {
            timer.bracketTime(INFO, "encryptEverything", () -> entityEncryptionService.encrypt(CASCADE_ANY, a, b, c, d));
            timer.bracketTime(INFO, "saveEverything", () -> save(a, b, c, d));
        });
        System.out.println("saved everything");
        Cache cache = entityManagerFactory.getCache().unwrap(Cache.class);

        // this automatically persists the entities; no need to call the 'save()' method
        transactionManager.commit(writeTxStatus);

        TransactionStatus readTxStatus = transactionManager.getTransaction(new DefaultTransactionDefinition());

        System.out.println("before personRepository.findAll");
        List<PersonEntity> people = withPassthrough(() -> personRepository.findAll());
        System.out.println("after findAll, starting bulk decrypt");
        // entityEncryptionService.decrypt(people);
        System.out.println("isInitialized=" + Hibernate.isInitialized(people.get(0).companies));
        entityEncryptionService.decrypt(CASCADE_SAVE, people);
        System.out.println("after decrypt");

        alice = personRepository.findById(alice.getId()).orElseThrow(IllegalStateException::new);
        bob = personRepository.findById(bob.getId()).orElseThrow(IllegalStateException::new);
        cindy = personRepository.findById(cindy.getId()).orElseThrow(IllegalStateException::new);
        dave = personRepository.findById(dave.getId()).orElseThrow(IllegalStateException::new);

        List<CompanyEntity> aliceCompanies = alice.getCompanies();
        assertEquals(aliceCompanies.size(), 2);
        assertTrue(aliceCompanies.contains(bankOfAmerica));
        assertTrue(aliceCompanies.contains(chase));

        List<CompanyEntity> bobCompanies = bob.getCompanies();
        assertEquals(bobCompanies.size(), 1);
        assertTrue(bobCompanies.contains(bankOfAmerica));

        List<CompanyEntity> cindyCompanies = cindy.getCompanies();
        assertEquals(cindyCompanies.size(), 2);
        assertTrue(cindyCompanies.contains(chase));
        assertTrue(cindyCompanies.contains(wellsFargo));

        List<CompanyEntity> daveCompanies = dave.getCompanies();
        assertEquals(daveCompanies.size(), 3);
        assertTrue(daveCompanies.contains(bankOfAmerica));
        assertTrue(daveCompanies.contains(citibank));
        assertTrue(daveCompanies.contains(wellsFargo));

        bankOfAmerica = companyRepository.findById(bankOfAmerica.getId()).orElseThrow(IllegalStateException::new);
        chase = companyRepository.findById(chase.getId()).orElseThrow(IllegalStateException::new);
        citibank = companyRepository.findById(citibank.getId()).orElseThrow(IllegalStateException::new);
        wellsFargo = companyRepository.findById(wellsFargo.getId()).orElseThrow(IllegalStateException::new);

        Set<PersonEntity> bankOfAmericaPeople = bankOfAmerica.getPeople();
        assertEquals(bankOfAmerica.getPeople().size(), 3);
        assertTrue(bankOfAmericaPeople.contains(alice));
        assertTrue(bankOfAmericaPeople.contains(bob));
        assertTrue(bankOfAmericaPeople.contains(dave));

        Set<PersonEntity> chasePeople = chase.getPeople();
        assertEquals(chasePeople.size(), 2);
        assertTrue(chasePeople.contains(alice));
        assertTrue(chasePeople.contains(cindy));

        Set<PersonEntity> citibankPeople = citibank.getPeople();
        assertEquals(citibankPeople.size(), 1);
        assertTrue(citibankPeople.contains(dave));

        Set<PersonEntity> wellsFargoPeople = wellsFargo.getPeople();
        assertEquals(wellsFargoPeople.size(), 2);
        assertTrue(wellsFargoPeople.contains(cindy));
        assertTrue(wellsFargoPeople.contains(dave));

        transactionManager.commit(readTxStatus);
        System.out.println("companiesTest complete");
    }

    private void save(PersonEntity... people) {
        personRepository.saveAll(asList(people));
    }

    private void save(CompanyEntity... companies) {
        companyRepository.saveAll(asList(companies));
    }

    private PersonEntity createPerson(String name) {
        PersonEntity personEntity = new PersonEntity();
        personEntity.setName(name);
        personEntity.setEmail(name + "@gmail.com");
        personEntity.setJson(wrap(() -> mapper.readTree("[1,2,3]")));
        personEntity.setTenant("tenant1");
        personEntity.setLastModifiedDate(Instant.now());
        return personEntity;
    }

    private CompanyEntity createCompany(String name) {
        CompanyEntity companyEntity = new CompanyEntity();
        companyEntity.setName(name);
        companyEntity.setTenant("tenant1");
        return companyEntity;
    }

    @Test
    public void findAll() {
        execute(() -> {
            entityEncryptionService.setDefaultMigrationMode(DUAL_WRITE);
            try {
                int numEntities = 10;
                JsonNode jsonNode = mapper.readTree("[1,2,3]");
                for (int i = 0; i < numEntities; i++) {
                    PersonEntity personEntity = new PersonEntity("user" + i + "@gmail.com", jsonNode);
                    personRepository.save(personEntity);
                }

                List<PersonEntity> fetchedEntities = personRepository.findAll();
                fetchedEntities.sort(Comparator.comparing(PersonEntity::getEmail));

                for (int i = 0; i < numEntities; i++) {
                    PersonEntity fetchedEntity = fetchedEntities.get(i);
                    assertNotNull(fetchedEntity);
                    assertEquals(fetchedEntity.getEmail(), "user" + i + "@gmail.com");
                    assertEquals(fetchedEntity.getJson().toString(), "[1,2,3]");
                    verifyRow(fetchedEntity.getEmail(), "PERSON", EMAIL_COLUMN, fetchedEntity.getId(), ENCRYPT, fetchedEntity);
                    verifyRow(
                            new String(jsonConverter.convertToDatabaseColumn(fetchedEntity.getJson())),
                            "PERSON",
                            JSON_COLUMN,
                            fetchedEntity.getId(),
                            DUAL_WRITE,
                            fetchedEntity);
                }
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    public void passthrough() {
        // String[] tenants = env.getRequiredProperty("rnet.encryption.localKms.testTenants").split(",");
        // Map<String, String> virtualKeys = EncryptionServiceConfig.findPropertiesByPrefix(env, "rnet.encryption.virtualKey");
        // VaultTopology topology = new VaultTopology("transit/rxrapid/dev/usw2/${tenant}");
        // setupVault(topology, tenants, virtualKeys, encryptionService);
        execute(() -> {
            entityEncryptionService.setDefaultMigrationMode(ENCRYPT);
            encryptionService.encrypt("foo".getBytes(), "nameKey", new TenantOption("tenant1"));
            encryptionService.encrypt("foo".getBytes(), "nameKey", new TenantOption("tenant1"));
            encryptionService.encrypt("foo".getBytes(), "nameKey", new TenantOption("tenant1"));
            encryptionService.encrypt("foo".getBytes(), "nameKey", new TenantOption("tenant1"));
            encryptionService.encrypt("foo".getBytes(), "nameKey", new TenantOption("tenant1"));

            PersonEntity person1 = new PersonEntity("one@gmail.com", mapper.readTree("[1]"));
            PersonEntity person2 = new PersonEntity("two@gmail.com", mapper.readTree("[2]"));
            PersonEntity person3 = new PersonEntity("three@gmail.com", mapper.readTree("[3]"));
            PersonEntity person4 = new PersonEntity("four@gmail.com", mapper.readTree("[4]"));
            PersonEntity person5 = new PersonEntity("five@gmail.com", mapper.readTree("[5]"));
            System.out.println("pre-encrypting entities");
            entityEncryptionService.encrypt(person1, person2, person3, person4, person5);
            entityEncryptionService.encrypt(person1);
            entityEncryptionService.encrypt(person2);
            entityEncryptionService.encrypt(person3);
            entityEncryptionService.encrypt(person4);
            entityEncryptionService.encrypt(person5);
            System.out.println("bulk encrypting entities");
            entityEncryptionService.encrypt(person1, person2, person3, person4, person5, person1, person2, person3, person4, person5);
            System.out.println("passthrough saveAll");
            withPassthrough(() -> personRepository.saveAll(asList(person1, person2, person3)));
            logger.info("\n\nafter saveAll\n");

            List<PersonEntity> people = withPassthrough(() -> personRepository.findAll());
            logger.info("\n\nafter passthrough findAll\n");
            people.forEach(person -> {
                // Email wasn't decrypted, so plaintext is null
                assertNull(person.getEmailEnc().getPlaintext());
                assertNotNull(person.getEmailEnc().getCryptotext());

                // Json wasn't encrypted in the first place
                assertNull(person.getEncryptedJson().getPlaintext());
                assertNotNull(person.getEncryptedJson().getCryptotext());
            });

            entityEncryptionService.encrypt(person1, person2, person3);
            assertEquals("one@gmail.com", person1.getEmail());
            assertEquals("two@gmail.com", person2.getEmail());
            assertEquals("three@gmail.com", person3.getEmail());
            assertEquals("[1]", person1.getJson().toString());
            assertEquals("[2]", person2.getJson().toString());
            assertEquals("[3]", person3.getJson().toString());
        });
    }

    private void verifyPerson(PersonEntity person, MigrationMode saveMode, String name, String email, String json) {
        verifyName(name, saveMode, person);
        verifyJson(json, saveMode, person);
        verifyEmail(email, person);
    }

    private void verifyName(String expectedPlaintext, MigrationMode saveMode, PersonEntity personEntity) {
        assertEquals(personEntity.getName(), expectedPlaintext);
        verify(expectedPlaintext, NAME_COLUMN, saveMode, personEntity);
    }

    private void verifyEmail(String expectedPlaintext, PersonEntity personEntity) {
        assertEquals(personEntity.getEmail(), expectedPlaintext);
        verify(expectedPlaintext, EMAIL_COLUMN, ENCRYPT, personEntity);
    }

    private void verifyJson(String expectedPlaintext, MigrationMode saveMode, PersonEntity personEntity) {
        JsonNode json = personEntity.getJson();
        if (expectedPlaintext == null) {
            assertNull(json);
        } else {
            assertNotNull(json);
            assertEquals(json.toString(), expectedPlaintext);
        }
        verify(expectedPlaintext, JSON_COLUMN, saveMode, personEntity);
    }

    private void verify(String expectedPlaintext, String column, MigrationMode saveMode, PersonEntity personEntity) {
        wrap(() ->
                assertEquals(verifyDbRows(
                        dataSource,
                        encryptionService,
                        PersonTest.PERSON_TABLE,
                        column,
                        expectedPlaintext,
                        saveMode,
                        getTenant(personEntity),
                        true,
                        entityEncryptionService.getEncryptionJobId()), 1)
        );
    }

    private void verifyRow(String expectedPlaintext, String table, String column, long id, MigrationMode saveMode, PersonEntity personEntity) {
        try {
            assertEquals(
                verifyDbRow(dataSource, encryptionService, table, column, expectedPlaintext, saveMode, getTenant(personEntity), id, true, entityEncryptionService.getEncryptionJobId()),
                1
            );
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    private void assertPersonJobNoCryptoUpdates(List<Long> rowIds) {
        long minRowId = rowIds.get(0);
        long maxRowId = rowIds.get(rowIds.size() - 1);
        EncryptedTableProcessor processor = new EncryptedTableProcessor(
                "PERSON[" + minRowId + "-" + maxRowId + "]",
                entityCache.get(PersonEntity.class.getName()),
                encryptionService,
                entityManager,
                transactionManager,
                rowIds,
                0,
                false,
                entityEncryptionService,
                false,
                Integer.MAX_VALUE
        );

        ProcessorResult result = processor.processRows();
        MigrationMode mode = entityEncryptionService.getDefaultMigrationMode();
        assertEquals(result.getNumRowsRequested(), rowIds.size());
        assertEquals(result.getNumRowsFound(), rowIds.size());
        assertEquals(result.getNumModifiedCryptoRows(), 0);
        assertEquals(result.getMigrationResult().getTotal(), 4);
        assertEquals(result.getMigrationResult().getIgnored(), 4);
        assertEquals(result.getMigrationResult().getModified(), 0);
        assertEquals(result.getMigrationResult().getEncrypted(), 0);
        assertEquals(result.getMigrationResult().getDecrypted(), 0);
        assertEquals(result.getMigrationResult().getVerificationFailed(), 0);
        assertEquals(result.getMigrationResult().getVerificationDecrypted(), mode == DUAL_WRITE ? 2 : 0);
    }

    @Test
    void jobIdValue_nullToNull() {
        executeJobIdValueTest(DUAL_WRITE,
            null, null, IGNORE_ENCRYPTION_JOB_ID,
            null, null, IGNORE_ENCRYPTION_JOB_ID
        );
    }

    @Test
    void jobIdValue_NonNullToNonNull() throws JsonProcessingException {
        executeJobIdValueTest(DUAL_WRITE,
            "v1", mapper.readTree("[1]"), entityEncryptionService.getEncryptionJobId(),
            "v2", mapper.readTree("[2]"), entityEncryptionService.getEncryptionJobId()
        );
    }

    @Test
    void jobIdValue_nullToNonNull() throws JsonProcessingException {
        executeJobIdValueTest(DUAL_WRITE,
            null, null, IGNORE_ENCRYPTION_JOB_ID,
            "v2", mapper.readTree("[2]"), entityEncryptionService.getEncryptionJobId()
        );
    }

    @Test
    void jobIdValue_nonNullToNull() throws JsonProcessingException {
        executeJobIdValueTest(DUAL_WRITE,
            "v1", mapper.readTree("[1]"), entityEncryptionService.getEncryptionJobId(),
            null, null, IGNORE_ENCRYPTION_JOB_ID
        );
    }

    @Test
    void jobIdValue_nullAndNotNull() throws JsonProcessingException {
        executeJobIdValueTest(DUAL_WRITE,
            null, mapper.readTree("[1]"), entityEncryptionService.getEncryptionJobId(),
            "v1", null, entityEncryptionService.getEncryptionJobId()
        );
    }

    @Test
    void jobIdValue_encryptMode() throws JsonProcessingException {
        executeJobIdValueTest(ENCRYPT,
            null, null, IGNORE_ENCRYPTION_JOB_ID,
            "v1", null, entityEncryptionService.getEncryptionJobId()
        );
        executeJobIdValueTest(ENCRYPT,
            null, null, IGNORE_ENCRYPTION_JOB_ID,
            null, mapper.readTree("[1]"), entityEncryptionService.getEncryptionJobId()
        );
    }

    @Test
    void jobIdValue_disabledMode() throws JsonProcessingException {
        executeJobIdValueTest(DISABLED,
            null, null, IGNORE_ENCRYPTION_JOB_ID,
            "v1", null, entityEncryptionService.getEncryptionJobId()
        );
        executeJobIdValueTest(DISABLED,
            null, null, IGNORE_ENCRYPTION_JOB_ID,
            null, mapper.readTree("[1]"), entityEncryptionService.getEncryptionJobId()
        );
    }

    @Test
    void jobIdValue_plaintextMode() throws JsonProcessingException {
        executeJobIdValueTest(PLAINTEXT,
            null, null, IGNORE_ENCRYPTION_JOB_ID,
            "v1", null, entityEncryptionService.getEncryptionJobId()
        );
        executeJobIdValueTest(PLAINTEXT,
            null, null, IGNORE_ENCRYPTION_JOB_ID,
            null, mapper.readTree("[1]"), entityEncryptionService.getEncryptionJobId()
        );
    }

    private void executeJobIdValueTest(
        MigrationMode migrationMode,
        String startingEmailValue, JsonNode startingJsonValue, String expectedStartingJobId,
        String updatedEmailValue, JsonNode updatedJsonValue, String expectedUpdatedJobId
    ) {
        execute(() -> {
            entityEncryptionService.setDefaultMigrationMode(migrationMode);

            PersonEntity person = new PersonEntity(startingEmailValue, startingJsonValue);

            PersonEntity persistedPerson = personRepository.saveAndFlush(person);

            assertEquals(persistedPerson.getEncryptionJobId(), expectedStartingJobId);

            persistedPerson.setEmail(updatedEmailValue);
            persistedPerson.setJson(updatedJsonValue);

            PersonEntity updatedPerson = personRepository.saveAndFlush(persistedPerson);

            assertEquals(updatedPerson.getEncryptionJobId(), expectedUpdatedJobId);
        });
    }
}
