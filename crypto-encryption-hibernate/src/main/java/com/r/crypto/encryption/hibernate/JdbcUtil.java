package com.r.crypto.encryption.hibernate;

import org.postgresql.PGConnection;
import org.postgresql.largeobject.LargeObject;
import org.postgresql.largeobject.LargeObjectManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.orm.jpa.vendor.Database;

import java.sql.Connection;
import java.sql.JDBCType;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Types;

import static com.r.crypto.util.Util.quote;
import static java.util.Arrays.asList;
import static org.springframework.orm.jpa.vendor.Database.H2;
import static org.springframework.orm.jpa.vendor.Database.ORACLE;
import static org.springframework.orm.jpa.vendor.Database.POSTGRESQL;
import static org.springframework.orm.jpa.vendor.Database.SQL_SERVER;

public class JdbcUtil {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final Database database;

    public JdbcUtil() {
        String dbName = System.getProperty("db");
        if (dbName == null) {
            database = H2;
        } else {
            switch (dbName) {
                case "h2":
                    database = H2;
                    break;
                case "oracle":
                    database = ORACLE;
                    break;
                case "mssql":
                    database = SQL_SERVER;
                    break;
                case "postgres":
                    database = POSTGRESQL;
                    break;
                default:
                    throw new IllegalStateException("unsupported db=" + quote(dbName));
            }
        }
    }

    public Database getDatabase() {
        return database;
    }

    public Object get(ResultSet rs, String column) throws SQLException {
        return get(rs, rs.findColumn(column));
    }

    public Object get(ResultSet rs, int columnIndex) throws SQLException {
        String type = rs.getMetaData().getColumnTypeName(columnIndex).toUpperCase();
        if (isPostgresOidBlob(type)) {
            return getPostgresOidBlob(rs, columnIndex);
        } else if (asList("BLOB", "BINARY", "VARBINARY").contains(type)) {
            byte[] bytes = rs.getBytes(columnIndex);
            return rs.wasNull() ? null : bytes;
        } else if (asList("VARCHAR", "CLOB").contains(type)) {
            String s = rs.getString(columnIndex);
            return rs.wasNull() ? null : s;
        } else {
            Object result = rs.getObject(columnIndex);
            return rs.wasNull() ? null : result;
        }
    }

    public void set(PreparedStatement stmt, int index, Object value, String type) throws SQLException {
        logger.trace("setting index=" + index + " type=" + type + " value=" + value);
        if (isPostgresOidBlob(type)) {
            setPostgresOidBlob(stmt, index, (byte[]) value);
        } else if (value instanceof byte[]) {
            stmt.setBytes(index, (byte[]) value);
        } else {
            stmt.setObject(index, value, toSqlType(type));
        }
    }

    public int toSqlType(String type) {
        if (isPostgresOidBlob(type)) {
            return Types.BIGINT;
        } else if (database == POSTGRESQL && "BYTEA".equals(type)) {
            return Types.BINARY;
        } else {
            return JDBCType.valueOf(type).getVendorTypeNumber();
        }
    }

    public boolean isPostgresOidBlob(String type) {
        return database == POSTGRESQL && ("OID".equals(type) || "BLOB".equals(type));
    }

    public boolean isPostgresOidBlob(ResultSet rs, int columnIndex) throws SQLException {
        if (database != POSTGRESQL) {
            return false;
        }

        ResultSetMetaData metadata = rs.getMetaData();
        return metadata.getColumnType(columnIndex) == Types.BIGINT
                && "OID".equalsIgnoreCase(metadata.getColumnTypeName(columnIndex));
    }

    /** See https://jdbc.postgresql.org/documentation/head/binary-data.html */
    private byte[] getPostgresOidBlob(ResultSet rs, int index) throws SQLException {
        Connection connection = rs.getStatement().getConnection();
        boolean autoCommit = connection.getAutoCommit();
        try {
            connection.setAutoCommit(false);
            LargeObjectManager largeObjectAPI = connection.unwrap(PGConnection.class).getLargeObjectAPI();
            long oid = rs.getLong(index);
            if (rs.wasNull()) {
                return null;
            }
            try (LargeObject obj = largeObjectAPI.open(oid, LargeObjectManager.READ)) {
                byte[] bytes = new byte[obj.size()];
                obj.read(bytes, 0, obj.size());
                return bytes;
            }
        } finally {
            connection.setAutoCommit(autoCommit);
        }
    }

    /** See https://jdbc.postgresql.org/documentation/head/binary-data.html */
    private void setPostgresOidBlob(PreparedStatement stmt, int colNum, byte[] bytes) throws SQLException {
        if (bytes == null) {
            stmt.setNull(colNum, Types.BIGINT);
        } else {
            Connection connection = stmt.getConnection();
            boolean autoCommit = connection.getAutoCommit();
            try {
                connection.setAutoCommit(false);
                LargeObjectManager largeObjectAPI = connection.unwrap(PGConnection.class).getLargeObjectAPI();
                long oid = largeObjectAPI.createLO(LargeObjectManager.READ | LargeObjectManager.WRITE);
                try (LargeObject obj = largeObjectAPI.open(oid, LargeObjectManager.WRITE)) {
                    obj.write(bytes, 0, bytes.length);
                    stmt.setLong(colNum, oid);
                }
            } finally {
                connection.setAutoCommit(autoCommit);
            }
        }
    }
}
