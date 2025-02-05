package com.r.crypto.encryption.jobs;

import com.r.crypto.encryption.migration.EncryptionData;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.r.crypto.util.Util.quote;

public class EncryptedRow {
    private final long id;
    private short version;
    private final Date lastModifiedDate;
    private final Map<String, EncryptionData> columnToDataMap = new HashMap<>();

    public EncryptedRow(long id, short version, Date lastModifiedDate) {
        this.id = id;
        this.version = version;
        this.lastModifiedDate = lastModifiedDate;
    }

    public long getId() {
        return id;
    }

    public short getVersion() {
        return version;
    }

    public void incrementVersion() {
        version++;
    }

    public Map<String, EncryptionData> getColumnToDataMap() {
        return columnToDataMap;
    }

    public EncryptionData getEncryptionData(String ciphertextColumnName) {
        return columnToDataMap.get(ciphertextColumnName);
    }

    public boolean hasModifiedData() {
        return columnToDataMap.values().stream().anyMatch(EncryptionData::isModified);
    }

    @Override
    public String toString() {
        return "EncryptedRow{"
                + "id=" + id
                + ", version=" + version
                + ", lastModifiedDate=" + quote(lastModifiedDate)
                + ", encryptionDataMap=" + columnToDataMap
                + '}';
    }
}
