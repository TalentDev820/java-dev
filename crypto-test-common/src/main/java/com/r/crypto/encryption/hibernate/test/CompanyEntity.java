package com.r.crypto.encryption.hibernate.test;

import com.r.crypto.encryption.hibernate.EncryptedEntity;
import com.r.crypto.encryption.hibernate.EncryptedEntityListener;
import com.r.crypto.encryption.hibernate.EncryptedString;
import com.r.crypto.encryption.hibernate.EncryptedStringType;
import org.hibernate.annotations.Columns;
import org.hibernate.annotations.Proxy;
import org.hibernate.annotations.TypeDef;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import static com.r.crypto.util.Util.quote;
import static java.util.stream.Collectors.toList;

@Entity
@Table(name = "COMPANY")
@Proxy(lazy = false)
@EntityListeners(value = EncryptedEntityListener.class)
@EncryptedEntity(tenantField = "tenant", encryptionJobIdField = "encryptionJobId")
@TypeDef(name = "EncryptedString", typeClass = EncryptedStringType.class, defaultForType = EncryptedString.class)
public class CompanyEntity {
    @SuppressWarnings("unused")
    private static final long serialVersionUID = -1;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(name = "TENANT")
    private String tenant;

    @Column(name = "ENCRYPTION_JOB_ID")
    private String encryptionJobId;

    @Columns(columns = {
            // Play with the order of the columns
            @Column(name = "NAME_ENC_HDR"),
            @Column(name = "NAME"),
            @Column(name = "NAME_ENC")
    })
    private EncryptedString nameEnc = new EncryptedString(this, "nameEnc");

    @ManyToMany(mappedBy = "companies", fetch = FetchType.EAGER)
    private Set<PersonEntity> people = new HashSet<>();

    public CompanyEntity() {}

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getTenant() {
        return tenant;
    }

    public void setTenant(String tenant) {
        this.tenant = tenant;
    }

    public String getName() {
        return nameEnc == null ? null : nameEnc.getPlaintext();
    }

    public void setName(String name) {
        nameEnc.updatePlaintext(name);
    }

    public Set<PersonEntity> getPeople() {
        return people;
    }

    public void setPeople(Set<PersonEntity> people) {
        this.people = people;
    }

    public String getEncryptionJobId() {
        return encryptionJobId;
    }

    public void setEncryptionJobId(String encryptionJobId) {
        this.encryptionJobId = encryptionJobId;
    }

    // CHECKSTYLE:OFF
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CompanyEntity that = (CompanyEntity) o;
        return id == that.id;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "CompanyEntity{"
                + "id=" + id
                + ", tenant=" + quote(tenant)
                + ", encryptionJobId=" + quote(encryptionJobId)
                + ", nameEnc=" + nameEnc
                + ", people=" + (people == null ? null : people.stream().map(PersonEntity::getId)).collect(toList())
                + "}";
    }
}
