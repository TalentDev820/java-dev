package com.r.crypto.encryption.hibernate;

import org.hibernate.CallbackException;
import org.hibernate.Interceptor;
import org.hibernate.Transaction;
import org.hibernate.metamodel.RepresentationMode;
import org.hibernate.type.Type;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import static com.r.crypto.util.Util.toSimpleString;

public class DebugInterceptor implements Interceptor {
    private static final Logger logger = LoggerFactory.getLogger(DebugInterceptor.class);

    public static final Map<String, Invocations> invocationsMap = new ConcurrentHashMap<>();

    public static void reset() {
        invocationsMap.clear();
    }

    public static Invocations getInvocations(String methodName) {
        invocationsMap.putIfAbsent(methodName, new Invocations(methodName));
        return invocationsMap.get(methodName);
    }

    @Override
    public boolean onLoad(Object entity, Serializable id, Object[] state, String[] propertyNames, Type[] types) throws CallbackException {
        logger.trace("onLoad: entity={} id={} propertyNames={} types={}",
                toSimpleString(entity),
                id,
                Arrays.toString(propertyNames),
                Arrays.toString(types)
        );
        record("onLoad", toSimpleString(entity), id, propertyNames, types);
        return false;
    }

    @Override
    public boolean onFlushDirty(
            Object entity,
            Serializable id,
            Object[] currentState,
            Object[] previousState,
            String[] propertyNames,
            Type[] types
    ) throws CallbackException {
        logger.trace("onFlushDirty: entity={} id={} propertyNames={} types={}",
                toSimpleString(entity),
                id,
                Arrays.toString(propertyNames),
                Arrays.toString(types)
        );
        record("onFlushDirty", toSimpleString(entity), id, propertyNames, types);
        return false;
    }

    @Override
    public boolean onSave(Object entity, Serializable id, Object[] state, String[] propertyNames, Type[] types) throws CallbackException {
        logger.trace("onSave: entity={} id={} state={} propertyNames={} types={}",
                entity,
                id,
                Arrays.toString(state),
                Arrays.toString(propertyNames),
                Arrays.toString(types)
        );
        record("onSave", toSimpleString(entity), id, propertyNames, types);
        return false;
    }

    @Override
    public void onDelete(Object entity, Serializable id, Object[] state, String[] propertyNames, Type[] types) throws CallbackException {
        logger.trace("onDelete: entity={} id={} propertyNames={} types={}",
                toSimpleString(entity),
                id,
                Arrays.toString(propertyNames),
                Arrays.toString(types)
        );
        record("onDelete", toSimpleString(entity), id, propertyNames, types);
    }

    @Override
    public void onCollectionRecreate(Object collection, Serializable key) throws CallbackException {
        logger.trace("onCollectionRecreate: collection={} key={}", toSimpleString(collection), key);
        record("onCollectionRecreate", "onCollectionRecreate", toSimpleString(collection), key);
    }

    @Override
    public void onCollectionRemove(Object collection, Serializable key) throws CallbackException {
        logger.trace("onCollectionRemove: collection={} key={}", toSimpleString(collection), key);
        record("onCollectionRemove", "onCollectionRemove", toSimpleString(collection), key);
    }

    @Override
    public void onCollectionUpdate(Object collection, Serializable key) throws CallbackException {
        logger.trace("onCollectionUpdate: collection={} key={}", toSimpleString(collection), key);
        record("onCollectionUpdate", "onCollectionUpdate", toSimpleString(collection), key);
    }

    @Override
    @SuppressWarnings("rawtypes")
    public void preFlush(Iterator entities) throws CallbackException {
        List<Object> entityList = new ArrayList<>();
        while (entities.hasNext()) {
            entityList.add(toSimpleString(entities.next()));
        }

        logger.trace("preFlush: {}", entityList);
        record("preFlush", "preFlush", entityList.toArray());
    }

    @Override
    @SuppressWarnings("rawtypes")
    public void postFlush(Iterator entities) throws CallbackException {
        List<String> entityList = new ArrayList<>();
        while (entities.hasNext()) {
            entityList.add(toSimpleString(entities.next()));
        }

        logger.trace("postFlush: {}", entityList);
        record("postFlush", "postFlush", entityList.toArray());
    }

    @Override
    public Boolean isTransient(Object entity) {
        logger.trace("isTransient: {}", toSimpleString(entity));
        record("isTransient", toSimpleString(entity));
        return null;
    }

    @Override
    public int[] findDirty(Object entity, Serializable id, Object[] currentState, Object[] previousState, String[] propertyNames, Type[] types) {
        if (logger.isTraceEnabled()) {
            logger.trace("findDirty: entity={} id={} propertyNames={} types={}",
                    toSimpleString(entity),
                    id,
                    Arrays.toString(propertyNames),
                    Arrays.toString(types)
            );
        }
        record("findDirty", toSimpleString(entity), id, propertyNames, types);
        return null;
    }

    @Override
    public Object instantiate(String entityName, RepresentationMode representationMode, Object id) throws CallbackException {
        logger.trace("instantiate: entityName={} representationMode={} id={}", entityName, representationMode, id);
        record("instantiate", entityName, representationMode, id);
        return null;
    }

    @Override
    public String getEntityName(Object object) throws CallbackException {
        logger.trace("getEntityName: {}", toSimpleString(object));
        record("getEntityName", toSimpleString(object));
        return null;
    }

    @Override
    public Object getEntity(String entityName, Serializable id) throws CallbackException {
        logger.trace("getEntity: entityName={} id={}", entityName, id);
        record("getEntity", entityName, id);
        return null;
    }

    @Override
    public void afterTransactionBegin(Transaction tx) {
        logger.trace("afterTransactionBegin: tx={}", tx);
        record("afterTransactionBegin", toSimpleString(tx), tx.getStatus().toString());
    }

    @Override
    public void beforeTransactionCompletion(Transaction tx) {
        logger.trace("beforeTransactionCompletion: tx={}", tx);
        record("beforeTransactionCompletion", toSimpleString(tx), tx.getStatus().toString());
    }

    @Override
    public void afterTransactionCompletion(Transaction tx) {
        logger.trace("afterTransactionCompletion: tx={}", tx);
        record("afterTransactionCompletion", toSimpleString(tx), tx.getStatus().toString());
    }

    private void record(String method, String operation, Object... data) {
        invocationsMap.computeIfAbsent(method, Invocations::new).add(operation, data);
    }

    public static class Operation {
        private final String name;
        private final Object[] data;

        public Operation(String name, Object... data) {
            this.name = name;
            this.data = data;
        }

        public String name() {
            return name;
        }

        public Object[] data() {
            return data;
        }
    }

    public static class Invocations {
        private final String methodName;
        private final AtomicLong count = new AtomicLong();
        private final Map<String, List<Operation>> operations = new ConcurrentHashMap<>();

        public Invocations(String methodName) {
            this.methodName = methodName;
        }

        public String methodName() {
            return methodName;
        }

        public AtomicLong count() {
            return count;
        }

        public Map<String, List<Operation>> operations() {
            return operations;
        }

        public List<Operation> operations(String operation) {
            operations.putIfAbsent(operation, new ArrayList<>());
            return operations.get(operation);
        }

        public void add(String operation, Object... data) {
            count.incrementAndGet();
            operations.computeIfAbsent(operation, op -> new ArrayList<>()).add(new Operation(operation, data));
        }
    }
}
