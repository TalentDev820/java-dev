package com.r.crypto.encryption.jobs.sample;

import jakarta.persistence.Column;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.Version;
import java.time.Instant;

@MappedSuperclass
public abstract class VersionedEntity {
    @Version
    @Column(name = "VERSION")
    public Short version;

    @Column(nullable = false, name = "MODIFIED_DTTM")
    public Instant lastModifiedDate;

    public Short getVersion() {
        return this.version;
    }

    public void setVersion(Short version) {
        this.version = version;
    }

    public Instant getLastModifiedDate() {
        return lastModifiedDate;
    }

    public void setLastModifiedDate(Instant lastModifiedDate) {
        this.lastModifiedDate = lastModifiedDate;
    }
}
