package com.r.crypto.encryption.jobs;

import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.option.TenantOption;
import com.r.crypto.encryption.exception.RCryptoEncryptionException;
import com.r.crypto.encryption.hibernate.EncryptedEntityModel;
import com.r.crypto.encryption.hibernate.EncryptedObject;
import com.r.crypto.encryption.hibernate.EncryptedTypeModel;
import com.r.crypto.encryption.hibernate.EntityEncryptionService;
import com.r.crypto.encryption.migration.EncryptionData;
import com.r.crypto.encryption.migration.MigrationMode;
import com.r.crypto.exception.RCryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static com.r.crypto.util.ExceptionWrapper.wrap;
import static com.r.crypto.util.LogUtil.debug;
import static com.r.crypto.util.LogUtil.trace;
import static com.r.crypto.util.Util.cast;
import static java.util.stream.Collectors.toList;

public class EncryptedTablePersistence {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final String jobName;
    private final EntityManager entityManager;
    private final PlatformTransactionManager transactionManager;
    private final EncryptedEntityModel entityModel;
    private final Instant ignoreAfterDate;
    private final boolean updateModifiedDate;
    private final EntityEncryptionService entityEncryptionService;

    public EncryptedTablePersistence(
            String jobName,
            EncryptedEntityModel entityModel,
            EntityManager entityManager,
            PlatformTransactionManager transactionManager,
            long ignoreTimeMs,
            boolean updateModifiedDate,
            EntityEncryptionService entityEncryptionService
    ) {
        this.jobName = jobName;
        this.entityModel = entityModel;
        this.entityManager = entityManager;
        this.transactionManager = transactionManager;
        this.ignoreAfterDate = entityModel.getModifiedDateFieldName() != null && ignoreTimeMs > 0
                ? Instant.ofEpochMilli(System.currentTimeMillis() - ignoreTimeMs)
                : null;
        this.updateModifiedDate = updateModifiedDate;
        this.entityEncryptionService = entityEncryptionService;
    }

    public List<EncryptedRow> fetchRows(List<Long> rowIds) {
        return wrap(RCryptoEncryptionException.class, () -> {
            String sql = createQuerySql();
            TypedQuery<Object[]> query = entityManager.createQuery(sql, Object[].class);
            query.setParameter("rowIds", rowIds);
            if (ignoreAfterDate != null) {
                query.setParameter("ignoreAfterDate", ignoreAfterDate);
            }

            List<EncryptedRow> rows = query.getResultList().stream().map(this::createEncryptedRow).collect(toList());
            logger.info("jobName=" + jobName + " found " + rows.size() + " rows");
            return rows;
        });
    }

    private String createQuerySql() {
        Collection<EncryptedTypeModel> typeModels = entityModel.getTypeModels();
        String modifiedDateFieldName = entityModel.getModifiedDateFieldName();
        List<String> fieldNames = new ArrayList<>(typeModels.size() + 5);

        fieldNames.add(entityModel.getIdFieldName());

        if (entityModel.getVersionFieldName() != null) {
            fieldNames.add(entityModel.getVersionFieldName());
        }
        if (modifiedDateFieldName != null) {
            fieldNames.add(modifiedDateFieldName);
        }
        if (entityModel.getTenantField() != null) {
            fieldNames.add(entityModel.getTenantFieldName());
        }

        typeModels.forEach(config -> fieldNames.add(config.getFieldName()));

        String sql = "SELECT " + String.join(",", fieldNames)
                + " FROM " + entityModel.getEntityClass().getName()
                + " WHERE " + entityModel.getIdFieldName() + " IN :rowIds"
                + (ignoreAfterDate == null ? "" : " AND " + modifiedDateFieldName + " < :ignoreAfterDate");

        debug(logger, () -> "jobName=" + jobName + " sql=" + sql);
        return sql;
    }

    private EncryptedRow createEncryptedRow(Object[] result) {
        int index = 0;

        long id = (Long) result[index++];
        short version = (entityModel.getVersionFieldName() == null) ? 0 : (Short) result[index++];
        Date lastModifiedDate = entityModel.getModifiedDateFieldName() == null ? null : Date.from((Instant) result[index++]);
        EncryptedRow encryptedRow = new EncryptedRow(id, version, lastModifiedDate);
        Map<String, EncryptionData> columnToDataMap = encryptedRow.getColumnToDataMap();

        String tenant = entityModel.getTenantField() == null
                ? null
                : entityModel.getTenantConverter().getTenantName(result[index++]);

        for (EncryptedTypeModel typeModel : entityModel.getTypeModels()) {
            EncryptedObject<Object> encryptedObject = cast(result[index++]);
            byte[] plaintext = typeModel.hasPlaintextColumn()
                    ? typeModel.convertPlaintextToBytes(encryptedObject.getPlaintext())
                    : null;

            MigrationMode migrationMode = typeModel.hasPlaintextColumn()
                    ? entityEncryptionService.getTenantMigrationMode(tenant)
                    : MigrationMode.ENCRYPT;

            EncryptionData encryptionData = new EncryptionData(
                    entityModel.getEntityTypeName() + "{" + id + "," + typeModel.getFieldName() + "}",
                    migrationMode,
                    typeModel.getVirtualKey(),
                    plaintext,
                    encryptedObject.getCryptotext(),
                    TenantOption.valueOf(tenant)
            );
            columnToDataMap.put(typeModel.getCiphertextColumnName(), encryptionData);
        }

        trace(logger, () -> "jobName=" + jobName + " created " + encryptedRow);
        return encryptedRow;
    }

    public void updateRowsInTransaction(List<EncryptedRow> rows) {
        wrap(RCryptoEncryptionException.class, () -> {
            TransactionTemplate tx = new TransactionTemplate(transactionManager);
            tx.executeWithoutResult(status -> updateRows(rows));
            trace(logger, () -> "jobName=" + jobName + " updated " + rows.size() + " rows");
        });
    }

    private void updateRows(List<EncryptedRow> rows) {
        Instant timestamp = Instant.now();
        for (EncryptedRow row : rows) {
            try {
                Query query = createUpdateQuery(row);
                Map<String, EncryptionData> columnToDataMap = row.getColumnToDataMap();
                query.setParameter("id", row.getId());
                query.setParameter("encryptionJobId", entityEncryptionService.getEncryptionJobId());

                if (entityModel.getVersionFieldName() != null) {
                    query.setParameter("oldVersion", row.getVersion());
                    row.incrementVersion();
                    query.setParameter("newVersion", row.getVersion());
                }
                if (updateModifiedDate && entityModel.getModifiedDateFieldName() != null) {
                    query.setParameter("modifiedDate", timestamp);
                }

                for (EncryptedTypeModel typeModel : entityModel.getTypeModels()) {
                    EncryptionData encryptionData = columnToDataMap.get(typeModel.getCiphertextColumnName());
                    if (encryptionData.isModified()) {
                        String fieldName = typeModel.getFieldName();
                        Cryptotext cryptotext = encryptionData.getCryptotext();

                        if (typeModel.hasPlaintextColumn()) {
                            Object plaintextColumnObject = typeModel.convertBytesToColumn(encryptionData.getPlaintext());
                            query.setParameter(fieldName + "_plaintext", plaintextColumnObject);
                        }

                        if (cryptotext == null) {
                            query.setParameter(fieldName + "_ciphertext", null);
                            query.setParameter(fieldName + "_ciphertextHeader", null);
                        } else {
                            query.setParameter(fieldName + "_ciphertext", cryptotext.getData());
                            query.setParameter(fieldName + "_ciphertextHeader", cryptotext.header());
                        }
                    }
                }

                query.executeUpdate();
                trace(logger, () -> "jobName=" + jobName + " updated " + row);
            } catch (Throwable t) {
                logger.error(t + " updating jobName=" + jobName + " " + row);
                throw new RCryptoException("error updating jobName=" + jobName + " rowId=" + row.getId(), t);
            }
        }
    }

    private Query createUpdateQuery(EncryptedRow row) {
        StringBuilder b = new StringBuilder("UPDATE ")
                .append(entityModel.getEntityClass().getName())
                .append(" SET ")
                .append(entityModel.getEncryptionJobIdFieldName()).append("=:encryptionJobId,");

        if (entityModel.getVersionFieldName() != null) {
            b.append(entityModel.getVersionFieldName()).append("=:newVersion,");
        }

        if (updateModifiedDate && entityModel.getModifiedDateFieldName() != null) {
            b.append(entityModel.getModifiedDateFieldName()).append("=:modifiedDate,");
        }

        List<String> updatedFields = new ArrayList<>(entityModel.getTypeModels().size());
        for (EncryptedTypeModel typeModel : entityModel.getTypeModels()) {
            EncryptionData encryptionData = row.getEncryptionData(typeModel.getCiphertextColumnName());
            if (encryptionData.isModified()) {
                String fieldName = typeModel.getFieldName();
                updatedFields.add(fieldName);
                if (typeModel.hasPlaintextColumn()) {
                    b.append(fieldName).append(".plaintext=:").append(fieldName).append("_plaintext,");
                }
                b.append(fieldName).append(".ciphertext=:").append(fieldName).append("_ciphertext,");
                b.append(fieldName).append(".ciphertextHeader=:").append(fieldName).append("_ciphertextHeader,");
            }
        }

        b.setCharAt(b.length() - 1, ' ');
        b.append("WHERE ").append(entityModel.getIdFieldName()).append("=:id");
        if (entityModel.getVersionFieldName() != null) {
            b.append(" AND ").append(entityModel.getVersionFieldName()).append("=:oldVersion");
        }

        trace(logger, () -> "created update query jobName=" + jobName + " fields=" + updatedFields + " updateSql=" + b);
        return entityManager.createQuery(b.toString());
    }
}
