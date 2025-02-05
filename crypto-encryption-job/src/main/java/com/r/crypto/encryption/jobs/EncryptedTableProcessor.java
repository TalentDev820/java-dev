package com.r.crypto.encryption.jobs;

import static java.util.stream.Collectors.toList;

import com.google.common.collect.Lists;
import com.r.crypto.encryption.api.service.REncryptionService;
import com.r.crypto.encryption.hibernate.EncryptedEntityModel;
import com.r.crypto.encryption.hibernate.EntityEncryptionService;
import com.r.crypto.encryption.migration.EncryptionData;
import com.r.crypto.encryption.migration.MigrationProcessor;
import com.r.crypto.encryption.migration.MigrationResult;
import com.r.crypto.exception.RCryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.PlatformTransactionManager;

import javax.persistence.EntityManager;
import java.util.List;

/**
 * Migrates (encrypts, re-encrypts or decrypts) the encrypted column data for a range of rows in a db table
 */
public class EncryptedTableProcessor {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final String jobName;
    private final REncryptionService encryptionService;
    private final List<Long> rowIds;
    private final EncryptedTablePersistence persistence;
    private final EntityEncryptionService entityEncryptionService;
    private final boolean processWrites;
    private final int batchSize;

    public EncryptedTableProcessor(
            String jobName,
            EncryptedEntityModel entityModel,
            REncryptionService encryptionService,
            EntityManager entityManager,
            PlatformTransactionManager transactionManager,
            List<Long> rowIds,
            long ignoreTimeMs,
            boolean updateModifiedDate,
            EntityEncryptionService entityEncryptionService,
            boolean processWrites,
            int batchSize
    ) {
        this.jobName = jobName;
        this.encryptionService = encryptionService;
        this.rowIds = rowIds;
        this.entityEncryptionService = entityEncryptionService;
        this.processWrites = processWrites;
        this.batchSize = batchSize;
        this.persistence = new EncryptedTablePersistence(
                jobName,
                entityModel,
                entityManager,
                transactionManager,
                ignoreTimeMs,
                updateModifiedDate,
                entityEncryptionService
        );
    }

    public ProcessorResult processRows() {
        logger.info("started processing jobName=" + jobName);
        try {
            ProcessorResult result = new ProcessorResult(0L, 0L);
            if (rowIds.isEmpty()) {
                return result;
            }

            int batchNumber = 0;
            List<List<Long>> rowIdBatches = Lists.partition(rowIds, batchSize);
            for (List<Long> rowIdBatch : rowIdBatches) {
                batchNumber++;
                try {
                    List<EncryptedRow> rows = persistence.fetchRows(rowIdBatch);
                    result.numRowsRequested += rowIdBatch.size();
                    result.numRowsFound += rows.size();

                    // create List of EncryptionData objects for all rows and all columns
                    List<EncryptionData> dataList = rows.stream()
                        .flatMap(row -> row.getColumnToDataMap().values().stream())
                        .collect(toList());

                    // verify that ciphertext matches plaintext
                    MigrationProcessor migrationProcessor = new MigrationProcessor(
                        dataList,
                        encryptionService,
                        entityEncryptionService.isBatchEncryptionEnabled()
                    );

                    // encrypt/decrypt
                    result.addMigrationResult(migrationProcessor.migrate());

                    if (processWrites) {
                        persistence.updateRowsInTransaction(rows);
                    }
                    result.numModifiedCryptoRows += rows.stream().filter(EncryptedRow::hasModifiedData).count();
                    result.numBatchesProcessed++;
                } catch (Throwable t) {
                    result.numBatchesFailed++;
                    logger.error("error processing"
                            + " jobName=" + jobName
                            + " batchNumber=" + batchNumber
                            + " rowsIds=[" + rowIdBatch.get(0) + " - " + rowIdBatch.get(rowIdBatch.size() - 1),
                            t);
                }
            }

            logger.info("completed jobName=" + jobName + " result=" + result);
            return result;
        } catch (Throwable t) {
            logger.error("error processing jobName=" + jobName, t);
            throw new RCryptoException("error processing jobName=" + jobName, t);
        }
    }

    public static class ProcessorResult {
        private long numBatchesProcessed;
        private long numBatchesFailed;
        private long numRowsRequested;
        private long numRowsFound;
        private long numModifiedCryptoRows;
        private MigrationResult migrationResult;

        public ProcessorResult(long numRowsRequested, long numRowsFound) {
            this.numRowsRequested = numRowsRequested;
            this.numRowsFound = numRowsFound;
            this.migrationResult = new MigrationResult();
        }

        public long getNumBatchesProcessed() {
            return numBatchesProcessed;
        }

        public long getNumBatchesFailed() {
            return numBatchesFailed;
        }

        public long getNumRowsRequested() {
            return numRowsRequested;
        }

        public MigrationResult getMigrationResult() {
            return migrationResult;
        }

        public long getNumRowsFound() {
            return numRowsFound;
        }

        public long getNumModifiedCryptoRows() {
            return numModifiedCryptoRows;
        }

        public void addMigrationResult(MigrationResult result) {
            this.migrationResult = this.migrationResult.add(result);
        }

        @Override
        public String toString() {
            return "ProcessorResult{"
                    + "numRowsRequested=" + numRowsRequested
                    + ", numRowsFound=" + numRowsFound
                    + ", numModifiedCryptoRows=" + numModifiedCryptoRows
                    + ", numBatchesProcessed=" + numBatchesProcessed
                    + ", numFailedBatches=" + numBatchesFailed
                    + ", migrationResult=" + migrationResult
                    + "}";
        }
    }
}
