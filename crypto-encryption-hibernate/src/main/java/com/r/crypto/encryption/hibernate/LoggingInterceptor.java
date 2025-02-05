package com.r.crypto.encryption.hibernate;

import org.hibernate.CallbackException;
import org.hibernate.EntityMode;
import org.hibernate.Interceptor;
import org.hibernate.Transaction;
import org.hibernate.type.Type;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Iterator;

public class LoggingInterceptor implements Interceptor {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    public boolean onLoad(Object entity, Serializable id, Object[] state, String[] propertyNames, Type[] types) throws CallbackException {
        logger.debug("onLoad");
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
        logger.debug("onFlushDirty");
        return false;
    }

    @Override
    public boolean onSave(Object entity, Serializable id, Object[] state, String[] propertyNames, Type[] types) throws CallbackException {
        logger.debug("onSave");
        return false;
    }

    @Override
    public void onDelete(Object entity, Serializable id, Object[] state, String[] propertyNames, Type[] types) throws CallbackException {
        logger.debug("onDelete");
    }

    @Override
    public void onCollectionRecreate(Object collection, Serializable key) throws CallbackException {
        logger.debug("onCollectionRecreate");
    }

    @Override
    public void onCollectionRemove(Object collection, Serializable key) throws CallbackException {
        logger.debug("onCollectionRemove");
    }

    @Override
    public void onCollectionUpdate(Object collection, Serializable key) throws CallbackException {
        logger.debug("onCollectionUpdate");
    }

    @Override
    @SuppressWarnings("rawtypes")
    public void preFlush(Iterator entities) throws CallbackException {
        logger.debug("preFlush");
    }

    @Override
    @SuppressWarnings("rawtypes")
    public void postFlush(Iterator entities) throws CallbackException {
        logger.debug("postFlush");
    }

    @Override
    public Boolean isTransient(Object entity) {
        logger.debug("isTransient");
        return null;
    }

    @Override
    public int[] findDirty(Object entity, Serializable id, Object[] currentState, Object[] previousState, String[] propertyNames, Type[] types) {
        logger.debug("findDirty");
        return null;
    }

    @Override
    public Object instantiate(String entityName, EntityMode entityMode, Serializable id) throws CallbackException {
        logger.debug("instantiate");
        return null;
    }

    @Override
    public String getEntityName(Object object) throws CallbackException {
        logger.debug("getEntityName");
        return null;
    }

    @Override
    public Object getEntity(String entityName, Serializable id) throws CallbackException {
        logger.debug("getEntity");
        return null;
    }

    @Override
    public void afterTransactionBegin(Transaction tx) {
        logger.debug("afterTransactionBegin");
    }

    @Override
    public void beforeTransactionCompletion(Transaction tx) {
        logger.debug("beforeTransactionCompletion");
    }

    @Override
    public void afterTransactionCompletion(Transaction tx) {
        logger.debug("afterTransactionCompletion");
    }

    @Override
    @SuppressWarnings("deprecation")
    public String onPrepareStatement(String sql) {
        logger.debug("onPrepareStatement");
        return null;
    }
}
