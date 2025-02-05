package com.r.crypto.encryption.jobs.sample;

import javax.persistence.Column;
import javax.persistence.MappedSuperclass;
import javax.persistence.Version;
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
