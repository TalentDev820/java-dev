package com.r.crypto.encryption.hibernate;

import static com.r.crypto.encryption.hibernate.EncryptedObject.Lifecycle.ENTITY_DECRYPTED;
import static com.r.crypto.encryption.hibernate.EncryptedObject.Lifecycle.ENTITY_ENCRYPTED;
import static com.r.crypto.encryption.migration.MigrationMode.DISABLED;
import static com.r.crypto.encryption.migration.MigrationMode.ENCRYPT;
import static com.r.crypto.encryption.migration.MigrationMode.PLAINTEXT;
import static com.r.crypto.util.ExceptionWrapper.wrap;
import static com.r.crypto.util.Util.isEmpty;
import static com.r.crypto.util.Util.quote;
import static com.r.crypto.util.Util.toSimpleString;
import static java.util.Collections.emptySet;
import static java.util.Objects.requireNonNull;

import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.option.TenantOption;
import com.r.crypto.encryption.api.EncryptionItem;
import com.r.crypto.encryption.api.service.REncryptionService;
import com.r.crypto.encryption.exception.RCryptoEncryptionException;
import com.r.crypto.encryption.migration.MigrationMode;
import com.r.crypto.exception.RCryptoConsistencyException;
import java.lang.reflect.Field;
import java.util.Collection;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Objects;
import jakarta.persistence.CascadeType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

@Component
public class EntityEncryptionService {
    /**
     * Value used for the entity's Encryption Job ID column value
     * when none of it's encryptable rows have values.
     * <p>
     * The encryption job can then filter out these rows at the database level
     * since there's nothing to re-encrypt.
     */
    public static final String IGNORE_ENCRYPTION_JOB_ID = "ignore";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Lazy
    @Autowired
    private EncryptedEntityCache entityCache;

    @Autowired
    private REncryptionService encryptionService;

    @Autowired
    private MigrationMode defaultMigrationMode;

    @Autowired
    @Qualifier("tenantMigrationModes")
    private Map<String, MigrationMode> tenantMigrationModes;

    @Value("${rnet.encryption.softFail.enabled:true}")
    private boolean softFailEnabled;

    @Value("${rnet.encryption.batchEncryption.enabled:false}")
    private boolean batchEncryptionEnabled;

    @Value("${rnet.encryption.job.id:0}")
    private String encryptionJobId;

    public void encrypt(Object... entities) {
        encrypt(emptySet(), entities);
    }

    public void encrypt(Collection<CascadeType> cascades, Object... objects) {
        if (isEmpty(objects)) {
            return;
        }

        EntityCrawler crawler = new EntityCrawler(entityCache, false, cascades, objects);
        Map<EncryptedObject<Object>, Object> encryptedObjects = crawler.crawl();
        Map<EncryptedObject<Object>, EncryptionItem> itemsMap = new HashMap<>();
        encryptedObjects.forEach((encryptedObject, parentEntity) -> prepareItem(true, encryptedObject, parentEntity, itemsMap));
        assignEncryptionJobId(encryptedObjects);

        encryptionService.process(itemsMap.values(), batchEncryptionEnabled);
        for (Map.Entry<EncryptedObject<Object>, EncryptionItem> entry : itemsMap.entrySet()) {
            EncryptedObject<Object> encryptedObject = entry.getKey();
            EncryptionItem item = entry.getValue();
            if (item.successful()) {
                encryptedObject.setCryptotext(item.getCryptotext());
                EncryptedTypeModel typeModel = encryptedObject.getTypeModel();
                Object plaintext = encryptedObject.getPlaintext();
                encryptedObject.setEncryptedPlaintext(typeModel.isMutable()
                        ? typeModel.convertBytesToPlaintext(typeModel.convertPlaintextToBytes(plaintext))
                        : plaintext);
            } else {
                MigrationMode mode = getTenantMigrationMode(encryptedObject.getTenant());
                if (softFailEnabled && mode.supportsSoftFail()) {
                    logger.error("encryption failed,"
                                    + " virtualKey=" + quote(item.getVirtualKey())
                                    + " kmsKey=" + quote(item.getKmsKey())
                                    + " tenant=" + quote(encryptedObject.getTenant()),
                            item.getException());
                    encryptedObject.setTenant(null);
                    encryptedObject.setCryptotext(null);
                    encryptedObject.setEncryptedPlaintext(null);
                } else {
                    throw item.getException();
                }
            }
        }
    }

    public void decrypt(Object... entities) {
        decrypt(emptySet(), entities);
    }

    public void decrypt(Collection<CascadeType> cascades, Object... objects) {
        if (isEmpty(objects)) {
            return;
        }

        EntityCrawler crawler = new EntityCrawler(entityCache, false, cascades, objects);
        Map<EncryptedObject<Object>, Object> encryptedObjects = crawler.crawl();
        Map<EncryptedObject<Object>, EncryptionItem> itemsMap = new HashMap<>();
        encryptedObjects.forEach((encryptedObject, parentEntity) ->
                prepareItem(false, encryptedObject, parentEntity, itemsMap)
        );

        if (!itemsMap.isEmpty()) {
            encryptionService.process(itemsMap.values(), batchEncryptionEnabled);

            itemsMap.forEach((encryptedObject, item) -> {
                EncryptedTypeModel typeModel = encryptedObject.getTypeModel();
                Object plaintext = encryptedObject.getPlaintext();
                Object decryptedPlaintext = typeModel.convertBytesToPlaintext(item.getPlaintext());

                if (item.successful() && plaintext != null) {
                    if (!Objects.equals(plaintext, decryptedPlaintext)) {
                        item.setException(new RCryptoConsistencyException("database plaintext does not match decrypted plaintext"));
                        logger.error("DCL plaintext=" + plaintext + " " + decryptedPlaintext + " " + encryptedObject);
                    }
                }

                if (item.successful()) {
                    encryptedObject.setPlaintext(decryptedPlaintext);
                    encryptedObject.setEncryptedPlaintext(typeModel.isMutable()
                            ? typeModel.convertBytesToPlaintext(item.getPlaintext())
                            : decryptedPlaintext);
                } else if (softFailEnabled
                        && plaintext != null
                        && encryptedObject.getCryptotext() != null) {
                    logger.error("decryption failed,"
                                    + " kmsKey=" + quote(item.getKmsKey())
                                    + " tenant=" + quote(encryptedObject.getTenant()),
                            item.getException());
                    encryptedObject.setTenant(null);
                    encryptedObject.setCryptotext(null);
                    encryptedObject.setEncryptedPlaintext(null);
                } else {
                    throw item.getException();
                }
            });
        }
    }

    private void prepareItem(
            boolean isEncryption,
            EncryptedObject<Object> encryptedObject,
            Object parentEntity,
            Map<EncryptedObject<Object>, EncryptionItem> itemsMap
    ) {
        encryptedObject.setLifecycle(isEncryption ? ENTITY_ENCRYPTED : ENTITY_DECRYPTED);
        assignAndValidateTenant(encryptedObject, parentEntity);
        assignSaveMode(isEncryption, encryptedObject);
        if (encryptedObject.getSaveMode() == DISABLED) {
            return;
        }

        EncryptionItem item = isEncryption ? prepareEncrypt(encryptedObject) : prepareDecrypt(encryptedObject);
        if (item != null) {
            itemsMap.put(encryptedObject, item);
        }
    }

    private void assignSaveMode(boolean isEncryptionItem, EncryptedObject<Object> encryptedObject) {
        EncryptedTypeModel typeModel = encryptedObject.getTypeModel();
        if (isEncryptionItem) {
            if (!typeModel.hasPlaintextColumn()) {
                encryptedObject.setSaveMode(ENCRYPT);
            } else if (!typeModel.hasCiphertextColumn()) {
                encryptedObject.setSaveMode(PLAINTEXT);
            } else {
                encryptedObject.setSaveMode(getTenantMigrationMode(encryptedObject.getTenant()));
            }
        } else {
            encryptedObject.setSaveMode(null);
        }
    }

    /** Validate the tenant, if any, across encryptedObject, parentEntity, and cryptotext */
    private void assignAndValidateTenant(EncryptedObject<Object> encryptedObject, Object parentEntity) {
        EncryptedEntityModel entityModel = encryptedObject.getTypeModel().getEntityModel();
        String objectTenant = encryptedObject.getTenant();
        String entityField = encryptedObject.getEntityField();

        // Nothing to do if this entity doesn't have a tenant
        if (entityModel.getTenantField() == null) {
            return;
        }

        if (parentEntity == null) {
            // If there's no parent entity, the encryptedObject must have its tenant set
            if (objectTenant == null) {
                throw new RCryptoConsistencyException(entityField + " tenant cannot be null");
            }
        } else {
            String entityTenant = entityModel.getTenant(parentEntity);
            if (entityTenant == null) {
                // The parent entity must have its tenant field set
                throw new RCryptoConsistencyException(parentEntity.getClass()
                        + " id=" + entityModel.getId(parentEntity)
                        + " missing tenant");
            } else if (objectTenant == null) {
                // Parent entity has tenant, copy it to the child field
                objectTenant = entityTenant;
                encryptedObject.setTenant(objectTenant);
            } else if (!entityTenant.equals(objectTenant)) {
                // If parent and child field have a tenant, they should be the same
                throw new RCryptoConsistencyException(entityField + " tenant=" + quote(objectTenant)
                        + " does not match entityTenant=" + quote(entityTenant)
                        + " id=" + entityModel.getId(parentEntity));
            }
        }

        // Cryptotext tenant must match the encryptedObject tenant
        Cryptotext cryptotext = encryptedObject.getCryptotext();
        if (cryptotext != null) {
            if (!objectTenant.equals(cryptotext.getTenant())) {
                throw new RCryptoConsistencyException(encryptedObject.getEntityField()
                        + " tenant=" + quote(objectTenant)
                        + " does not match cryptotext header tenant=" + quote(cryptotext.getTenant()));
            }
        }
    }

    private void assignEncryptionJobId(Map<EncryptedObject<Object>, Object> encryptedObjects) {
        IdentityHashMap<Object, Boolean> parentEntityToEncryptableMap = new IdentityHashMap<>();

        encryptedObjects.forEach((encryptedObject, parentEntity) -> {
            if (parentEntity != null) {
                EncryptedEntityModel entityModel = entityCache.get(parentEntity.getClass());
                if (entityModel.getEncryptionJobIdField() != null) {
                    boolean isObjectEncryptable = encryptedObject.hasEncryptableContent();
                    Boolean isEntityEncryptable = parentEntityToEncryptableMap.get(parentEntity);
                    if (isEntityEncryptable == null) {
                        // First time seeing this entity
                        parentEntityToEncryptableMap.put(parentEntity, isObjectEncryptable);
                    } else if (!isEntityEncryptable && isObjectEncryptable) {
                        // Previous fields were not encryptable but this one is
                        parentEntityToEncryptableMap.put(parentEntity, true);
                    }
                }
            }
        });

        parentEntityToEncryptableMap.forEach((parentEntity, isEncryptable) -> {
            EncryptedEntityModel entityModel = entityCache.get(parentEntity.getClass());
            String jobId = isEncryptable ? encryptionJobId : IGNORE_ENCRYPTION_JOB_ID;
            Field jobIdField = entityModel.getEncryptionJobIdField();
            wrap(RCryptoEncryptionException.class, () -> jobIdField.set(parentEntity, jobId));
        });
    }

    private EncryptionItem prepareEncrypt(EncryptedObject<Object> encryptedObject) {
        EncryptedTypeModel typeModel = encryptedObject.getTypeModel();
        Object plaintext = encryptedObject.getPlaintext();
        if (plaintext == null) {
            encryptedObject.setCryptotext(null);
            encryptedObject.setEncryptedPlaintext(null);
            return null;
        }

        EncryptionItem item = null;
        String tenant = encryptedObject.getTenant();
        MigrationMode mode = tenantMigrationModes.getOrDefault(tenant, defaultMigrationMode);

        if (mode.supportsCiphertext() || !typeModel.hasPlaintextColumn()) {
            if (encryptedObject.getCryptotext() != null) {
                // EncryptedObject.updatePlaintext deletes the cryptotext, so
                // if it's still set the plaintext hasn't been modified.
                if (typeModel.isImmutable()
                        || Objects.deepEquals(encryptedObject.getPlaintext(), encryptedObject.getEncryptedPlaintext())) {
                    logger.debug("already encrypted {}", encryptedObject);
                    return null;
                }
            }
            byte[] plaintextBytes = requireNonNull(typeModel.convertPlaintextToBytes(plaintext));
            item = new EncryptionItem(typeModel.getVirtualKey(), plaintextBytes, TenantOption.valueOf(tenant));
        } else {
            encryptedObject.setCryptotext(null);
            encryptedObject.setEncryptedPlaintext(null);
        }

        return item;
    }

    private EncryptionItem prepareDecrypt(EncryptedObject<Object> encryptedObject) {
        Cryptotext cryptotext = encryptedObject.getCryptotext();
        if (cryptotext == null) {
            return null;
        }

        if (encryptedObject.getPlaintext() != null) {
            if (encryptedObject.getTypeModel().isImmutable()
                    || Objects.deepEquals(encryptedObject.getPlaintext(), encryptedObject.getEncryptedPlaintext())) {
                logger.debug("already decrypted {}", encryptedObject);
                return null;
            }
        }

        return new EncryptionItem(cryptotext, TenantOption.valueOf(encryptedObject.getTenant()));
    }

    public EncryptedEntityCache getEntityCache() {
        return entityCache;
    }

    public void setEntityCache(EncryptedEntityCache entityCache) {
        this.entityCache = entityCache;
    }

    public REncryptionService getEncryptionService() {
        return encryptionService;
    }

    public void setEncryptionService(REncryptionService encryptionService) {
        this.encryptionService = encryptionService;
    }

    public MigrationMode getDefaultMigrationMode() {
        return defaultMigrationMode;
    }

    public void setDefaultMigrationMode(MigrationMode defaultMigrationMode) {
        this.defaultMigrationMode = defaultMigrationMode;
    }

    public Map<String, MigrationMode> getTenantMigrationModes() {
        return tenantMigrationModes;
    }

    public MigrationMode getTenantMigrationMode(String tenant) {
        return tenantMigrationModes.getOrDefault(tenant, defaultMigrationMode);
    }

    public void setTenantMigrationModes(Map<String, MigrationMode> tenantMigrationModes) {
        this.tenantMigrationModes = tenantMigrationModes;
    }

    public String getEncryptionJobId() {
        return encryptionJobId;
    }

    public void setEncryptionJobId(String encryptionJobId) {
        this.encryptionJobId = encryptionJobId;
    }

    public boolean isSoftFailEnabled() {
        return softFailEnabled;
    }

    public void setSoftFailEnabled(boolean softFailEnabled) {
        this.softFailEnabled = softFailEnabled;
    }

    public boolean isBatchEncryptionEnabled() {
        return batchEncryptionEnabled;
    }

    public void setBatchEncryptionEnabled(boolean batchEncryptionEnabled) {
        this.batchEncryptionEnabled = batchEncryptionEnabled;
    }

    @Override
    public String toString() {
        return toSimpleString(this) + "{"
                + "entityCache=" + toSimpleString(entityCache)
                + ", encryptionService=" + encryptionService
                + ", defaultMigrationMode=" + defaultMigrationMode
                + ", tenantMigrationModes=" + tenantMigrationModes
                + ", batchEncryption=" + batchEncryptionEnabled
                + ", softFail=" + softFailEnabled
                + "}";
    }
}
