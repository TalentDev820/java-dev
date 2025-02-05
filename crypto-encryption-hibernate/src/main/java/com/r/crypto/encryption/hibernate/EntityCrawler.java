package com.r.crypto.encryption.hibernate;

import com.r.crypto.util.Timer;
import com.r.crypto.util.Timer.TimedResult;
import org.hibernate.Hibernate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.persistence.CascadeType;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static com.r.crypto.util.ExceptionWrapper.wrap;
import static com.r.crypto.util.LogUtil.trace;
import static com.r.crypto.util.Util.cast;
import static com.r.crypto.util.Util.isEmpty;
import static com.r.crypto.util.Util.toSimpleString;
import static java.lang.System.identityHashCode;
import static java.util.Arrays.asList;
import static java.util.Collections.singleton;

public class EntityCrawler {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final Timer timer = new Timer(logger);

    private final Object[] objects;
    private final boolean processLazy;
    private final Set<CascadeType> cascades = new HashSet<>();
    private final EncryptedEntityCache entityCache;
    private final Set<Integer> scanned = new HashSet<>();
    private final Map<EncryptedObject<Object>, Object> encryptedObjects = new HashMap<>();

    public static final Set<CascadeType> CASCADE_ALL = new HashSet<>(asList(
            CascadeType.ALL,
            CascadeType.PERSIST,
            CascadeType.MERGE,
            CascadeType.REMOVE,
            CascadeType.REFRESH,
            CascadeType.DETACH
    ));

    public static final Set<CascadeType> CASCADE_NONE = singleton(null);

    public static final Set<CascadeType> CASCADE_ANY = new HashSet<>(asList(
            null,
            CascadeType.ALL,
            CascadeType.PERSIST,
            CascadeType.MERGE,
            CascadeType.REMOVE,
            CascadeType.REFRESH,
            CascadeType.DETACH
    ));

    public static final Set<CascadeType> CASCADE_SAVE = new HashSet<>(asList(
            CascadeType.ALL,
            CascadeType.PERSIST,
            CascadeType.MERGE
    ));

    public EntityCrawler(
            EncryptedEntityCache entityCache,
            boolean processLazy,
            Collection<CascadeType> cascades,
            Object... objects) {
        this.objects = objects;
        this.processLazy = processLazy;
        this.entityCache = entityCache;

        if (!isEmpty(cascades)) {
            this.cascades.addAll(cascades);
        }
    }

    public Map<EncryptedObject<Object>, Object> crawl() {
        return timer.bracketTimedResult("crawl processLazy=%s cascades=%s", processLazy, cascades, () -> {
            Arrays.stream(objects).forEach(this::crawl);
            if (logger.isTraceEnabled()) {
                logger.trace("results:");
                AtomicInteger i = new AtomicInteger(1);
                encryptedObjects.forEach((encryptedObject, parentEntity) ->
                        logger.trace(String.format("    %d: %15s %s",
                                i.getAndIncrement(),
                                encryptedObject,
                                toSimpleString(parentEntity)))
                );
            }
            return new TimedResult<>(encryptedObjects, "encryptedObjects=%d scanned=%d", encryptedObjects.size(), scanned.size());
        });
    }

    public int getTotalScanned() {
        return scanned.size();
    }

    private void crawl(Object object) {
        if (object == null) {
            return;
        }

        boolean alreadyScanned = !scanned.add(identityHashCode(object));
        if (alreadyScanned) {
            trace(logger, () -> "    found already scanned object=" + toSimpleString(object));
            return;
        }

        if (object instanceof EncryptedObject) {
            logger.trace("    found encryptedObject={}", object);
            encryptedObjects.put(cast(object), null);
        } else if (object instanceof Iterable) {
            trace(logger, () -> "    found iterable=" + toSimpleString(object));
            Iterable<Object> iterable = cast(object);
            iterable.forEach(this::crawl);
        } else if (object instanceof Map) {
            trace(logger, () -> "    found map=" + toSimpleString(object));
            Map<Object, Object> map = cast(object);
            map.keySet().forEach(this::crawl);
            map.values().forEach(this::crawl);
        } else if (object.getClass().isArray() && !object.getClass().getComponentType().isPrimitive()) {
            trace(logger, () -> "    found array=" + toSimpleString(object));
            Arrays.stream((Object[]) object).forEach(this::crawl);
        } else if (object instanceof Optional) {
            Optional<Object> optional = cast(object);
            trace(logger, () -> "    "
                    + "found optional=" + toSimpleString(object)
                    + optional.map(o -> " value=" + toSimpleString(o)).orElse(""));
            optional.ifPresent(this::crawl);
        } else {
            EncryptedEntityModel entityModel = entityCache.get(object.getClass());
            if (entityModel == null) {
                trace(logger, () -> "    found leaf object=" + toSimpleString(object));
                return;
            }

            trace(logger, () -> "    "
                    + "found encryptedEntity=" + toSimpleString(object)
                    + " typeName=" + entityModel.getEntityTypeName());
            Collection<EncryptedTypeModel> typeModels = entityModel.getTypeModels();
            typeModels.forEach(typeModel -> {
                EncryptedObject<Object> encryptedObject = typeModel.getEncryptedObject(object);
                if (handleLazy(encryptedObject, typeModel.getSimpleFieldName())) {
                    logger.trace("        adding field={} encryptedObject={}", typeModel.getFieldName(), encryptedObject);
                    if (!scanned.add(identityHashCode(encryptedObject)) || encryptedObjects.containsKey(encryptedObject)) {
                        throw new IllegalStateException("already scanned " + encryptedObject + " entity=" + toSimpleString(object));
                    }
                    encryptedObjects.put(encryptedObject, object);
                }
            });

            entityModel.getAssociationCascades().forEach((field, fieldCascades) -> {
                if (shouldCascade(cascades, fieldCascades)) {
                    Object value = wrap(() -> field.get(object));
                    if (handleLazy(value, field.getName())) {
                        logger.trace("        crawling field={} value={} cascades={}",
                                object.getClass().getSimpleName() + "." + field.getName(),
                                toSimpleString(value),
                                fieldCascades
                        );
                        crawl(value);
                    }
                }
            });
        }
    }

    private boolean handleLazy(Object object, String fieldName) {
        if (Hibernate.isInitialized(object)) {
            return true;
        }

        trace(logger, () -> "        "
                + (processLazy ? "loading" : "ignoring")
                + " lazy field=" + fieldName
                + " value=" + toSimpleString(object));

        if (processLazy) {
            Hibernate.initialize(object);
            return true;
        } else {
            return false;
        }
    }

    public static boolean shouldCascade(Set<CascadeType> cascades, Set<CascadeType> fieldCascades) {
        // Asked to process "null" cascade, which means don't cascade anything
        if (isEmpty(cascades)) {
            return false;
        }

        if (isEmpty(fieldCascades) && cascades.contains(null)) {
            return true;
        }

        Set<CascadeType> intersection = new HashSet<>(cascades);
        intersection.retainAll(fieldCascades);
        return !intersection.isEmpty();
    }
}
