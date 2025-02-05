package com.r.crypto.encryption.hibernate.test;

import com.r.crypto.encryption.hibernate.EncryptedEntityListener;
import com.r.crypto.encryption.hibernate.EncryptedString;
import com.r.crypto.encryption.hibernate.EncryptedStringType;
import com.r.crypto.encryption.hibernate.EncryptedEntity;
import com.r.crypto.encryption.jobs.sample.VersionedEntity;
import org.hibernate.annotations.Columns;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "NO_TENANT")
@EncryptedEntity(lastModifiedDateField = "lastModifiedDate")
@EntityListeners(value = EncryptedEntityListener.class)
@TypeDef(
        name = "EncryptedStringType",
        typeClass = EncryptedStringType.class,
        defaultForType = EncryptedString.class
)
public class NoTenantEntity extends VersionedEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Columns(columns = {
            @Column(name = "NAME"),
            @Column(name = "NAME_ENC"),
            @Column(name = "NAME_ENC_HDR")
    })
    @Type(type = "EncryptedStringType")
    private EncryptedString nameEnc = new EncryptedString(this, "nameEnc");

    public NoTenantEntity() {
        setLastModifiedDate(Instant.now());
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getName() {
        return nameEnc.getPlaintext();
    }

    public void setName(String name) {
        nameEnc.updatePlaintext(name);
    }

    @Override
    public String toString() {
        return "NoTenantEntity{"
                + "id=" + id
                + ", nameEnc=" + nameEnc
                + ", version=" + version
                + ", lastModifiedDate=" + lastModifiedDate
                + "}";
    }
}
