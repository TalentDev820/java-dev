package com.r.crypto.encryption.hibernate.test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.r.crypto.encryption.hibernate.EncryptedEntity;
import com.r.crypto.encryption.hibernate.EncryptedEntityListener;
import com.r.crypto.encryption.hibernate.EncryptedObject;
import com.r.crypto.encryption.hibernate.EncryptedString;
import com.r.crypto.encryption.hibernate.EncryptedStringType;
import com.r.crypto.encryption.hibernate.EncryptedType;
import com.r.crypto.encryption.jobs.sample.VersionedEntity;
import org.hibernate.annotations.Columns;
import org.hibernate.annotations.Parameter;
import org.hibernate.annotations.Proxy;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static com.r.crypto.util.ExceptionWrapper.wrap;
import static com.r.crypto.util.Util.quote;
import static com.r.crypto.util.Util.toSimpleString;

@Entity
@Table(name = "PERSON")
@Proxy(lazy = false)
@EncryptedEntity(
        tenantField = "tenant",
        lastModifiedDateField = "lastModifiedDate",
        encryptionJobIdField = "encryptionJobId"
)
@EntityListeners(value = EncryptedEntityListener.class)
@TypeDef(name = "EncryptedType", typeClass = EncryptedType.class, defaultForType = EncryptedObject.class)
@TypeDef(name = "EncryptedStringType", typeClass = EncryptedStringType.class, defaultForType = EncryptedString.class)
public class PersonEntity extends VersionedEntity {
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
            @Column(name = "PLAINTEXT")
    })
    @Type(type = "EncryptedStringType")
    private EncryptedString plaintextEnc = new EncryptedString(this, "plaintextEnc");

    @Columns(columns = {
            @Column(name = "NAME"),
            @Column(name = "NAME_ENC"),
            @Column(name = "NAME_ENC_HDR")
    })
    // Strings aren't mutable, but make sure everything works anyway
    @Type(type = "EncryptedStringType", parameters = @Parameter(name = "mutable", value = "true"))
    private EncryptedString nameEnc = new EncryptedString(this, "nameEnc");

    @Columns(columns = {
            @Column(name = "EMAIL_ENC"),
            @Column(name = "EMAIL_ENC_HDR")
    })
    private EncryptedString emailEnc = new EncryptedString(this, "emailEnc");

    @Columns(columns = {
            @Column(name = "JSON"),
            @Column(name = "JSON_ENC"),
            @Column(name = "JSON_ENC_HDR")
    })
    @Converts(value = {
            @Convert(attributeName = "plaintextToBytesConverter", converter = JsonNodeToBytesConverter.class),
            @Convert(attributeName = "plaintextToColumnConverter", converter = JsonNodeToBytesConverter.class)
    })
    @Type(
            type = "EncryptedType",
            parameters = {
                    @Parameter(name = "mutable", value = "true"),
                    @Parameter(name = "virtualKey", value = "jsonKey"),
                    @Parameter(name = "plaintextColumnType", value = "BinaryType"),
            }
    )
    private EncryptedObject<JsonNode> encryptedJson = new EncryptedObject<>(this, "encryptedJson");

    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private CompanyEntity company;

    @OneToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinColumn(name = "prev_company_id")
    private CompanyEntity previousCompany;

    @ManyToMany(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinTable(
            name = "COMPANY_PERSON",
            joinColumns = @JoinColumn(name = "person_id"),
            inverseJoinColumns = @JoinColumn(name = "company_id")
    )
    public List<CompanyEntity> companies = new ArrayList<>();

    public PersonEntity() {}

    public PersonEntity(String name, String email) {
        setName(name);
        setEmail(email);
        setLastModifiedDate(Instant.now());
        this.tenant = "tenant1";
    }

    public PersonEntity(String name) {
        setName(name);
        setLastModifiedDate(Instant.now());
        this.tenant = "tenant1";
    }

    public PersonEntity(String email, JsonNode jsonNode) {
        setEmail(email);
        setJson(jsonNode);
        setLastModifiedDate(Instant.now());
        this.tenant = "tenant1";
    }

    public PersonEntity(String name, String email, JsonNode json) {
        this(name, email);
        setJson(json);
    }

    public PersonEntity(String name, String email, String json) {
        this(name, email);
        setJson(json == null ? null : wrap(() -> new ObjectMapper().readTree(json)));
    }

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

    public CompanyEntity getCompany() {
        return company;
    }

    public void setCompany(CompanyEntity company) {
        this.company = company;
    }

    public CompanyEntity getPreviousCompany() {
        return previousCompany;
    }

    public void setPreviousCompany(CompanyEntity previousCompany) {
        this.previousCompany = previousCompany;
    }

    public List<CompanyEntity> getCompanies() {
        return companies;
    }

    public void setCompanies(List<CompanyEntity> companies) {
        this.companies = companies;
    }

    public String getName() {
        return nameEnc.getPlaintext();
    }

    public void setName(String name) {
        nameEnc.updatePlaintext(name);
    }

    public String getEmail() {
        return emailEnc.getPlaintext();
    }

    public void setEmail(String email) {
        this.emailEnc.updatePlaintext(email);
    }

    public JsonNode getJson() {
        return encryptedJson.getPlaintext();
    }

    public void setJson(JsonNode json) {
        this.encryptedJson.updatePlaintext(json);
    }

    public EncryptedString getNameEnc() {
        return nameEnc;
    }

    public void setNameEnc(EncryptedString nameEnc) {
        this.nameEnc = nameEnc;
    }

    public EncryptedObject<String> getEmailEnc() {
        return emailEnc;
    }

    public void setEmailEnc(EncryptedString emailEnc) {
        this.emailEnc = emailEnc;
    }

    public EncryptedObject<JsonNode> getEncryptedJson() {
        return encryptedJson;
    }

    public void setEncryptedJson(EncryptedObject<JsonNode> encryptedJson) {
        this.encryptedJson = encryptedJson;
    }

    public String getEncryptionJobId() {
        return encryptionJobId;
    }

    public void setEncryptionJobId(String encryptionJobId) {
        this.encryptionJobId = encryptionJobId;
    }

    public String getPlaintext() {
        return plaintextEnc.getPlaintext();
    }

    public void setPlaintext(String plaintext) {
        this.plaintextEnc.updatePlaintext(plaintext);
    }

    @Override
    public String toString() {
        return toSimpleString(this) + "{"
                + "id=" + id
                + ", emailEnc=" + emailEnc
                + ", encryptedJson=" + encryptedJson
                + ", nameEnc=" + nameEnc
                + ", plaintext=" + plaintextEnc
                + ", tenant=" + quote(tenant)
                + ", version=" + version
                + ", lastModifiedDate=" + lastModifiedDate
                + "}";
    }
}
