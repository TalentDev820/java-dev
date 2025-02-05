package com.r.crypto.encryption.hibernate;

import static com.r.crypto.util.ExceptionWrapper.wrap;
import static com.r.crypto.util.LogUtil.debug;
import static com.r.crypto.util.LogUtil.isEnabled;
import static com.r.crypto.util.Util.toSimpleString;
import static org.slf4j.event.Level.DEBUG;
import static org.slf4j.event.Level.TRACE;

import com.r.crypto.encryption.exception.RCryptoEncryptionException;
import com.r.crypto.util.ThrowingRunnable;
import com.r.crypto.util.ThrowingSupplier;
import com.r.crypto.util.Timer;
import javax.persistence.PostLoad;
import javax.persistence.PostPersist;
import javax.persistence.PostRemove;
import javax.persistence.PostUpdate;
import javax.persistence.PrePersist;
import javax.persistence.PreRemove;
import javax.persistence.PreUpdate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class EncryptedEntityListener {
    private static final ThreadLocal<Boolean> passthrough = new ThreadLocal<>();
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final Timer timer = new Timer(logger, RCryptoEncryptionException.class);

    @Autowired
    private EntityEncryptionService entityEncryptionService;

    public EntityEncryptionService getEntityEncryptionService() {
        return entityEncryptionService;
    }

    public void setEntityEncryptionService(EntityEncryptionService entityEncryptionService) {
        this.entityEncryptionService = entityEncryptionService;
    }

    public static void withPassthrough(ThrowingRunnable runnable) {
        Boolean originalPassthrough = passthrough.get();
        try {
            passthrough.set(true);
            wrap(RCryptoEncryptionException.class, runnable);
        } finally {
            passthrough.set(originalPassthrough);
        }
    }

    public static <T> T withPassthrough(ThrowingSupplier<T> supplier) {
        Boolean originalPassthrough = passthrough.get();
        try {
            passthrough.set(true);
            return wrap(RCryptoEncryptionException.class, supplier);
        } finally {
            passthrough.set(originalPassthrough);
        }
    }

    public static boolean isPassthroughEnabled() {
        return passthrough.get() == Boolean.TRUE;
    }

    @PrePersist
    public void prePersist(Object entity) {
        execute("prePersist encrypt", entity, () -> entityEncryptionService.encrypt(entity));
    }

    @PreUpdate
    public void preUpdate(Object entity) {
        execute("preUpdate encrypt", entity, () -> entityEncryptionService.encrypt(entity));
    }

    @PostLoad
    public void postLoad(Object entity) {
        execute("postLoad decrypt", entity, () -> entityEncryptionService.decrypt(entity));
    }

    private void execute(String method, Object entity, ThrowingRunnable runnable) {
        if (isPassthroughEnabled()) {
            debug(logger, () -> "passthrough " + method + " entity=" + toSimpleString(entity));
        } else if (isEnabled(logger, TRACE)) {
            timer.bracketTime(TRACE, () -> method + " entity=" + entity, runnable);
        } else if (isEnabled(logger, DEBUG)) {
            timer.time(DEBUG, () -> method + " entity=" + toSimpleString(entity), runnable);
        } else {
            wrap(RCryptoEncryptionException.class, runnable);
        }
    }

    @PostUpdate
    public void postUpdate(Object entity) {
        logger.trace("postUpdate: {}", entity);
    }

    @PostPersist
    public void postPersist(Object entity) {
        logger.trace("postPersist: {}", entity);
    }

    @PreRemove
    public void preRemove(Object entity) {
        logger.trace("preRemove: {}", entity);
    }

    @PostRemove
    public void postRemove(Object entity) {
        logger.trace("postRemove: {}", entity);
    }

    @Override
    public String toString() {
        return toSimpleString(this) + "{" + entityEncryptionService + "}";
    }
}
