package com.r.crypto.encryption.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.option.TenantOption;
import com.r.crypto.encryption.api.service.REncryptionService;
import com.r.crypto.encryption.hibernate.DebugInterceptor;
import com.r.crypto.encryption.hibernate.EncryptedEntity;
import com.r.crypto.encryption.hibernate.JdbcUtil;
import com.r.crypto.encryption.migration.MigrationMode;
import com.r.crypto.util.ThrowingRunnable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.lang.reflect.Field;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static com.r.crypto.encryption.hibernate.test.PersonTest.EMAIL_COLUMN;
import static com.r.crypto.util.ExceptionWrapper.wrap;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class TestUtils {
    private static final Logger logger = LoggerFactory.getLogger(TestUtils.class);
    private static final JdbcUtil jdbcUtil = new JdbcUtil();

    public static void verifyNonEncryptedDbRows(
            DataSource dataSource,
            String column,
            String table,
            String expectedValue
    ) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            String sql = "SELECT " + column + " FROM " + table;
            try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                ResultSet rs = stmt.executeQuery();
                while (rs.next()) {
                    String plaintext = getPlaintext(rs, 1);
                    assertEquals(plaintext, expectedValue);
                }
            }
        } catch (Throwable t) {
            logger.error(t + " in verifyNonEncryptedDbRows for " + table + "." + column + " expectedValue=" + expectedValue, t);
            throw new RuntimeException(t);
        }
    }

    public static int verifyDbRows(
            DataSource dataSource,
            REncryptionService encryptionService,
            String table,
            String column,
            String expectedPlaintext,
            MigrationMode saveMode,
            String tenant,
            boolean hasJobIdColumn,
            String expectedJobIdValue
    ) {
        return verifyDbRow(dataSource, encryptionService, table, column, expectedPlaintext, saveMode, tenant, null, hasJobIdColumn, expectedJobIdValue);
    }

    public static int verifyDbRow(
            DataSource dataSource,
            REncryptionService encryptionService,
            String table,
            String column,
            String expectedPlaintext,
            MigrationMode saveMode,
            String tenant,
            Long entityId,
            boolean hasJobIdColumn,
            String expectedJobIdValue
        ) {
        boolean unmappedPlaintext = EMAIL_COLUMN.equals(column);
        if (unmappedPlaintext && !saveMode.supportsCiphertext()) {
            throw new IllegalStateException("entity field without plaintext column must be encrypted");
        }

        String sql = "SELECT" +
                (unmappedPlaintext ? " 'unmapped', " : " " + column + ", ")
                + column + "_ENC_HDR, "
                + column + "_ENC"
                + (hasJobIdColumn ? ", ENCRYPTION_JOB_ID" : "")
                + " FROM " + table
                + (entityId == null ? "" : " WHERE ID = ?");

        try {
            try (Connection connection = dataSource.getConnection()) {
                connection.setAutoCommit(false);
                try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                    if (entityId != null) {
                        stmt.setLong(1, entityId);
                    }
                    return checkRows(stmt, expectedPlaintext, saveMode, encryptionService, tenant, unmappedPlaintext, hasJobIdColumn, expectedJobIdValue);
                }
            }
        } catch (Throwable t) {
            logger.error(t + " in verifyDbRow"
                    + " entityId=" + entityId
                    + " " + table + "." + column
                    + " expectedPlaintext=" + expectedPlaintext
                    + " saveMode=" + saveMode);
            throw new RuntimeException(t);
        }
    }

    private static int checkRows(
            PreparedStatement stmt,
            String expectedPlaintext,
            MigrationMode saveMode,
            REncryptionService encryptionService,
            String tenant,
            boolean unmappedPlaintext,
            boolean hasJobIdColumn,
            String expectedJobIdValue
    ) throws SQLException {
        int count = 0;

        ResultSet rs = stmt.executeQuery();
        while (rs.next()) {
            count++;
            if (!unmappedPlaintext) {
                String plaintext = getPlaintext(rs, 1);
                if (saveMode.supportsPlaintext()) {
                    assertEquals(plaintext, expectedPlaintext);
                } else {
                    assertNull(plaintext);
                }
            }

            if (expectedPlaintext == null && !unmappedPlaintext) {
                assertNull(rs.getString(2));
                assertTrue(rs.wasNull());
                assertNull(rs.getBytes(3));
                assertTrue(rs.wasNull());
            }

            if (expectedPlaintext == null || (!unmappedPlaintext && !saveMode.supportsCiphertext())) {
                assertNull(rs.getString(2));
                assertTrue(rs.wasNull());
                assertNull(rs.getBytes(3));
                assertTrue(rs.wasNull());
            } else {
                String header = rs.getString(2);
                assertNotNull(header);
                assertNotEquals(header.length(), 0);

                byte[] ciphertext = (byte[]) jdbcUtil.get(rs, 3);
                Cryptotext cryptotext = Cryptotext.parse(header, ciphertext);
                assertNotNull(cryptotext);
                assertEquals(
                        encryptionService.decrypt(cryptotext, new TenantOption(tenant)),
                        expectedPlaintext.getBytes(UTF_8)
                );
            }

            if (hasJobIdColumn) {
                assertEquals(rs.getString(4), expectedJobIdValue);
            }
        }

        return count;
    }

    public static String getPlaintext(ResultSet rs, String column) throws SQLException {
        return getPlaintext(rs, rs.findColumn(column));
    }

    public static String getPlaintext(ResultSet rs, int columnIndex) throws SQLException {
        Object plaintextColumnObject = jdbcUtil.get(rs, columnIndex);
        if (plaintextColumnObject == null) {
            return null;
        } else if (plaintextColumnObject instanceof byte[]) {
            return new String((byte[]) plaintextColumnObject, UTF_8);
        } else {
            return String.valueOf(plaintextColumnObject);
        }
    }

    public static String getTenant(Object entity) throws IllegalAccessException {
        EncryptedEntity encryptedEntity = entity.getClass().getAnnotation(EncryptedEntity.class);
        if (encryptedEntity != null) {
            String tenantFieldName = encryptedEntity.tenantField();
            Field[] allFields = entity.getClass().getDeclaredFields();
            List<Field> tenantFields = Arrays.stream(allFields)
                    .filter(field -> field.getName().equals(tenantFieldName))
                    .collect(Collectors.toList());
            assertTrue(tenantFields.size() < 2);
            Field field = tenantFieldName.isEmpty() ? null : tenantFields.get(0);
            if (field != null) {
                field.setAccessible(true);
                return String.valueOf(field.get(entity));
            }
        }
        return null;
    }

    /**
     * I have no idea why stack traces disappear in CI, but here we are.
     * Using this method also makes it easier to separate out log output.
     */
    public static void execute(String method, Logger methodLogger, ThrowingRunnable runnable) {
        Thread thread = Thread.currentThread();
        String threadName = thread.getName();
        String name = methodLogger.getName().substring(methodLogger.getName().lastIndexOf('.') + 1) + "." + method;
        try {
            thread.setName(name);
            methodLogger.info("\n\n======================== starting " + name + " ========================\n");
            runnable.run();
        } catch (Throwable t) {
            logger.error(t + " executing name=" + name, t);
            throw t instanceof RuntimeException ? (RuntimeException) t : new RuntimeException(t);
        } finally {
            methodLogger.info("\n\n======================== finished " + name + " ========================\n");
            thread.setName(threadName);
        }
    }

    public static void assertSqlCalls(int inserts, int updates, int selects, int deletes) {
        DebugInterceptor.Invocations statements = DebugInterceptor.getInvocations("onPrepareStatement");
        assertEquals(statements.operations("insert").size(), inserts, "inserts don't match");
        assertEquals(statements.operations("update").size(), updates, "updates don't match");
        assertEquals(statements.operations("select").size(), selects, "selects don't match");
        assertEquals(statements.operations("delete").size(), deletes, "deletes don't match");
    }

    public static JsonNode toJson(String s) {
        return s == null ? null : wrap(() -> new ObjectMapper().readTree(s));
    }
}
