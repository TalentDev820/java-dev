package com.r.crypto.encryption.hibernate;

import static com.r.crypto.util.Util.toSimpleString;

import com.r.crypto.encryption.exception.RCryptoEncryptionException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.metamodel.EntityType;
import jakarta.persistence.metamodel.Metamodel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

@Lazy
@Component
public class EncryptedEntityCache {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private ConcurrentHashMap<String, EncryptedEntityModel> encryptedEntityMap;

    public EncryptedEntityCache(
      @Qualifier("RCryptoEMF") EntityManagerFactory entityManagerFactory) {

        Metamodel metamodel = entityManagerFactory.getMetamodel();
        List<EncryptedEntityModel> entityModels = new ArrayList<>();

        for (EntityType<?> entityType : metamodel.getEntities()) {
            Class<?> entityClass = entityType.getJavaType();
            try {
                EncryptedEntityModel entityModel = EncryptedEntityModel.create(entityType);
                if (entityModel != null) {
                    entityModels.add(entityModel);
                    logger.info("created " + entityModel);
                }
            } catch (Throwable t) {
                throw new RCryptoEncryptionException(t + " processing entityClass=" + entityClass, t);
            }
        }

        encryptedEntityMap = new ConcurrentHashMap<>(entityModels.size());
        entityModels.forEach(model -> encryptedEntityMap.put(model.getEntityClass().getName(), model));
    }

    public EncryptedEntityModel get(Class<?> entityClass) {
        return encryptedEntityMap.get(entityClass.getName());
    }

    public EncryptedEntityModel get(String className) {
        return encryptedEntityMap.get(className);
    }

    public Collection<EncryptedEntityModel> entities() {
        return encryptedEntityMap.values();
    }

    @Override
    public String toString() {
        return toSimpleString(this) + "{entities=" + encryptedEntityMap.keySet() + "}";
    }
}
