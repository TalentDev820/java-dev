package com.r.crypto.encryption.hibernate;

import com.r.crypto.api.Cryptotext;
import com.r.crypto.encryption.exception.RCryptoEncryptionException;
import com.r.crypto.encryption.hibernate.converter.IdentityConverter;
import com.r.crypto.encryption.migration.MigrationMode;
import org.hibernate.HibernateException;
import org.hibernate.annotations.Columns;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.type.ByteArrayType;
import org.hibernate.type.StringType;
import org.hibernate.type.Type;
import org.hibernate.usertype.CompositeUserType;
import org.hibernate.usertype.DynamicParameterizedType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.orm.jpa.vendor.Database;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Converts;
import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import static com.r.crypto.encryption.hibernate.EncryptedObject.Lifecycle.READ;
import static com.r.crypto.encryption.hibernate.EncryptedObject.Lifecycle.WRITTEN;
import static com.r.crypto.util.ExceptionWrapper.wrap;
import static com.r.crypto.util.LogUtil.trace;
import static com.r.crypto.util.Util.cast;
import static com.r.crypto.util.Util.toSimpleString;
import static java.util.Objects.requireNonNull;

public class EncryptedType implements CompositeUserType, DynamicParameterizedType {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    protected static final JdbcUtil jdbcUtil = new JdbcUtil();
    protected static final Map<String, EncryptedTypeModel> entityFieldToTypeModelMap = new ConcurrentHashMap<>();

    protected String entityField;
    protected EncryptedTypeModel typeModel;
    protected String[] propertyNames;
    protected Type[] propertyTypes;

    public static EncryptedTypeModel getTypeModel(String entityField) {
        return entityFieldToTypeModelMap.get(entityField);
    }

    public static EncryptedTypeModel getTypeModel(Class<?> entityClass, String fieldName) {
        return getTypeModel(entityClass.getName() + "." + fieldName);
    }

    public EncryptedTypeModel model() {
        if (typeModel == null) {
            typeModel = entityFieldToTypeModelMap.computeIfAbsent(entityField, EncryptedTypeModel::new);
        }
        return typeModel;
    }

    @SuppressWarnings("unchecked")
    protected void initConfig(Properties parameters) {
        String accessType = parameters.getProperty(ACCESS_TYPE);
        if (!"field".equals(accessType)) {
            throw new IllegalStateException("access type " + accessType + " not supported");
        }

        if (entityField == null) {
            String className = parameters.getProperty(ENTITY);
            String fieldName = parameters.getProperty(PROPERTY);
            entityField = className + "." + fieldName;
            model().setEncryptedObjectClass(parameters.getProperty(RETURNED_CLASS));

            try {
                Class<?> entityClass = Class.forName(className);
                Field field = entityClass.getDeclaredField(fieldName);

                Columns columns = field.getAnnotation(Columns.class);
                if (columns != null) {
                    for (int i = 0; i < columns.columns().length; i++) {
                        Column column = columns.columns()[i];
                        if (column.name().toUpperCase().endsWith("_ENC")) {
                            typeModel.setCiphertextColumnName(column.name());
                            typeModel.setCiphertextColumnIndex(i);
                        } else if (column.name().toUpperCase().endsWith("_ENC_HDR")) {
                            typeModel.setCiphertextHeaderColumnName(column.name());
                            typeModel.setCiphertextHeaderColumnIndex(i);
                        } else {
                            typeModel.setPlaintextColumnName(column.name());
                            typeModel.setPlaintextColumnIndex(i);
                        }
                    }
                }

                typeModel.setColumnConverter(new IdentityConverter());
                Converts converts = field.getAnnotation(Converts.class);
                if (converts != null) {
                    for (Convert convert : converts.value()) {
                        Constructor<?> converterConstructor = convert.converter().getDeclaredConstructor();
                        switch (convert.attributeName()) {
                            case "plaintextToBytesConverter":
                                typeModel.setBytesConverter(cast(converterConstructor.newInstance()));
                                break;
                            case "plaintextToColumnConverter":
                                typeModel.setColumnConverter(cast(converterConstructor.newInstance()));
                                break;
                            default:
                                throw new IllegalStateException("unrecognized converter=" + convert.attributeName());
                        }
                    }
                }
            } catch (Exception e) {
                throw new RCryptoEncryptionException(e);
            }
        }
    }

    @Override
    public void setParameterValues(Properties parameters) {
        initConfig(parameters);

        if (virtualKey() == null && entityField.endsWith("Enc")) {
            typeModel.setVirtualKey(entityField.substring(entityField.lastIndexOf('.') + 1, entityField.length() - 3) + "Key");
        }

        if (plaintextColumnType() == null) {
            typeModel.setPlaintextColumnType(StringType.INSTANCE);
        }

        if (ciphertextColumnType() == null) {
            typeModel.setCiphertextColumnType(BinaryType.INSTANCE);
        }

        if (ciphertextHeaderColumnType() == null) {
            typeModel.setCiphertextHeaderColumnType(StringType.INSTANCE);
        }

        if (columnConverter() == null) {
            typeModel.setColumnConverter(new IdentityConverter());
        }

        typeModel.setVirtualKey(requireNonNull(parameters.getProperty("virtualKey", typeModel.getVirtualKey())));
        typeModel.setMutable(Boolean.parseBoolean(parameters.getProperty("mutable", String.valueOf(typeModel.isMutable()))));

        typeModel.setPlaintextColumnName(parameters.getProperty("plaintextColumnName", typeModel.getPlaintextColumnName()));
        typeModel.setPlaintextColumnType(findType(parameters, "plaintextColumnType", typeModel.getPlaintextColumnType(), jdbcUtil.getDatabase()));

        typeModel.setCiphertextColumnName(parameters.getProperty("ciphertextColumnName", typeModel.getCiphertextColumnName()));
        typeModel.setCiphertextColumnType(findType(parameters, "ciphertextColumnType", typeModel.getCiphertextColumnType(), jdbcUtil.getDatabase()));

        typeModel.setCiphertextHeaderColumnName(parameters.getProperty("ciphertextHeaderColumnName", typeModel.getCiphertextHeaderColumnName()));
        typeModel.setCiphertextHeaderColumnType(findType(
                parameters,
                "ciphertextHeaderColumnType",
                typeModel.getCiphertextHeaderColumnType(),
                jdbcUtil.getDatabase()
        ));

        int columnCount = 0;
        if (hasPlaintextColumn()) {
            columnCount++;
        }
        if (hasCiphertextColumn()) {
            columnCount += 2;
        }
        propertyNames = new String[columnCount];
        propertyTypes = new Type[columnCount];

        if (typeModel.hasPlaintextColumn()) {
            propertyNames[plaintextColumnIndex()] = "plaintext";
            propertyTypes[plaintextColumnIndex()] = plaintextColumnType();
        }
        if (typeModel.hasCiphertextColumn()) {
            if (!typeModel.hasCiphertextHeaderColumn()) {
                throw new IllegalStateException("ciphertext mapped but ciphertext header is not");
            }
            propertyNames[ciphertextColumnIndex()] = "ciphertext";
            propertyTypes[ciphertextColumnIndex()] = ciphertextColumnType();
            propertyNames[ciphertextHeaderColumnIndex()] = "ciphertextHeader";
            propertyTypes[ciphertextHeaderColumnIndex()] = ciphertextHeaderColumnType();
        }

        logger.debug("setParameterValues this={} typeModel={}", this, typeModel);
    }

    private Type findType(Properties parameters, String property, Type defaultType, Database database) {
        return wrap(RCryptoEncryptionException.class, () -> {
            String typeName = parameters.getProperty(property + "." + database.name());
            if (typeName == null) {
                typeName = parameters.getProperty(property);
                if (typeName == null) {
                    return defaultType;
                }
            }

            if (!typeName.contains(".")) {
                typeName = "org.hibernate.type." + typeName;
            }

            Class<Type> typeClass = cast(Class.forName(typeName));
            try {
                return (Type) typeClass.getField("INSTANCE").get(null);
            } catch (NoSuchFieldException e) {
                return typeClass.getDeclaredConstructor().newInstance();
            }
        });
    }

    @Override
    public String[] getPropertyNames() {
        return propertyNames;
    }

    @Override
    public Type[] getPropertyTypes() {
        return propertyTypes;
    }

    @Override
    public Object getPropertyValue(Object component, int propertyIndex) {
        trace(logger, () -> "getPropertyValue index=" + propertyIndex + " component=" + component);

        EncryptedObject<Object> encryptedObject = cast(component);
        if (propertyIndex == plaintextColumnIndex()) {
            return encryptedObject.getPlaintext();
        }

        Cryptotext cryptotext = encryptedObject.getCryptotext();
        if (cryptotext == null) {
            return null;
        } else if (propertyIndex == ciphertextColumnIndex()) {
            return cryptotext.getData();
        } else if (propertyIndex == ciphertextHeaderColumnIndex()) {
            return cryptotext.header();
        } else {
            throw new IllegalArgumentException("invalid propertyIndex=" + propertyIndex);
        }
    }

    @Override
    public void setPropertyValue(Object component, int propertyIndex, Object value) {
        trace(logger,
                () -> String.format("setPropertyValue component=%s propertyIndex=%d value=%s",
                        component,
                        propertyIndex,
                        toSimpleString(value)
                ));

        EncryptedObject<Object> encryptedObject = cast(component);
        if (propertyIndex == plaintextColumnIndex()) {
            encryptedObject.setPlaintext(value);
        }

        Cryptotext cryptotext = encryptedObject.getCryptotext();
        if (cryptotext == null && value == null) {
            return;
        }

        if (cryptotext == null) {
            cryptotext = new Cryptotext();
        }

        if (propertyIndex == ciphertextColumnIndex()) {
            cryptotext.setData((byte[]) value);
        } else if (propertyIndex == ciphertextHeaderColumnIndex()) {
            cryptotext = Cryptotext.parse((CharSequence) value, cryptotext.getData());
        }

        encryptedObject.setCryptotext(cryptotext);
    }

    @Override
    public Class<?> returnedClass() {
        logger.trace("returnedClass: entityField={} result={}",
                model().getSimpleFieldName(),
                model().getEncryptedObjectClass());
        return model().getEncryptedObjectClass();
    }

    @Override
    public boolean isMutable() {
        logger.trace("isMutable: entityField={} mutable={}", model().getSimpleFieldName(), model().isMutable());
        return model().isMutable();
    }

    @Override
    public Serializable disassemble(Object value, SharedSessionContractImplementor session) {
        Serializable result = value == null ? null : new SerializedEncryptedObject(cast(value));
        logger.trace("disassemble: value={} result={}", value, result);
        return result;
    }

    @Override
    public Object assemble(Serializable cached, SharedSessionContractImplementor session, Object owner) {
        Object result = cached == null ? null : ((SerializedEncryptedObject) cached).deserialize();
        logger.trace("assemble: cached={} result={}", cached, result);
        return result;
    }

    @Override
    public Object deepCopy(Object value) {
        EncryptedObject<Object> copy = null;
        if (value != null) {
            copy = model().createEncryptedObject();
            SerializedEncryptedObject.copy(cast(value), copy);
        }
        logger.trace("deepCopy: value={} copy={}", value, copy);
        return copy;
    }

    @Override
    public Object replace(Object original, Object target, SharedSessionContractImplementor session, Object owner) throws HibernateException {
        EncryptedObject<Object> src = cast(original);
        EncryptedObject<Object> dst = cast(target);
        SerializedEncryptedObject.copy(src, dst);
        logger.trace("replace: original={} target={}", original, target);
        return target;
    }

    @Override
    public int hashCode(Object x) throws HibernateException {
        int hash = new EncryptedObjectPersistentState(cast(x)).hashCode();
        logger.trace("hashCode: hash={} encryptedObject={}", hash, x);
        return hash;
    }

    @Override
    public boolean equals(Object x, Object y) throws HibernateException {
        EncryptedObjectPersistentState pso1 = new EncryptedObjectPersistentState(cast(x));
        EncryptedObjectPersistentState pso2 = new EncryptedObjectPersistentState(cast(y));
        boolean result = pso1.equals(pso2);
        logger.trace("equals: result={} x={} y={}", result, x, y);
        return result;
    }

    @Override
    public void nullSafeSet(PreparedStatement statement, Object value, int index, SharedSessionContractImplementor session)
            throws HibernateException, SQLException {
        logger.trace("nullSafeSet: index={} value={}", index, value);

        EncryptedObject<Object> encryptedObject = requireNonNull(cast(value));
        MigrationMode saveMode = requireNonNull(encryptedObject.getSaveMode());

        if (hasPlaintextColumn()) {
            Object dbPlaintext = saveMode.supportsPlaintext()
                    ? typeModel.convertPlaintextToColumn(encryptedObject.getPlaintext())
                    : null;
            plaintextColumnType().nullSafeSet(statement, dbPlaintext, index + plaintextColumnIndex(), session);
        }

        if (hasCiphertextColumn()) {
            Cryptotext cryptotext = saveMode.supportsCiphertext()
                    ? encryptedObject.getCryptotext()
                    : null;
            ciphertextColumnType().nullSafeSet(
                    statement,
                    cryptotext == null ? null : cryptotext.getData(),
                    index + ciphertextColumnIndex(),
                    session
            );

            ciphertextHeaderColumnType().nullSafeSet(
                    statement,
                    cryptotext == null ? null : cryptotext.header(),
                    index + ciphertextHeaderColumnIndex(),
                    session
            );
        }

        encryptedObject.setLifecycle(WRITTEN);
    }

    @Override
    public Object nullSafeGet(ResultSet rs, String[] names, SharedSessionContractImplementor session, Object owner)
            throws HibernateException, SQLException {
        EncryptedObject<Object> encryptedObject = model().createEncryptedObject();

        if (hasPlaintextColumn()) {
            Object dbPlaintext = plaintextColumnType().nullSafeGet(rs, names[plaintextColumnIndex()], session, owner);
            encryptedObject.setPlaintext(typeModel.convertColumnToPlaintext(dbPlaintext));
        }

        if (hasCiphertextColumn()) {
            byte[] ciphertext = (byte[]) ciphertextColumnType().nullSafeGet(rs, names[ciphertextColumnIndex()], session, owner);
            String header = (String) ciphertextHeaderColumnType().nullSafeGet(rs, names[ciphertextHeaderColumnIndex()], session, owner);
            Cryptotext cryptotext = Cryptotext.parse(header, ciphertext);
            encryptedObject.setCryptotext(cryptotext);
            encryptedObject.setTenant(cryptotext == null ? null : cryptotext.getOption("tenant"));
        }

        encryptedObject.setLifecycle(READ);
        logger.trace("nullSafeGet: result={}", encryptedObject);
        return encryptedObject;
    }

    public String entityField() {
        return entityField;
    }

    public String virtualKey() {
        return model().getVirtualKey();
    }

    public String plaintextColumnName() {
        return model().getPlaintextColumnName();
    }

    public Type plaintextColumnType() {
        return model().getPlaintextColumnType();
    }

    public int plaintextColumnIndex() {
        return model().getPlaintextColumnIndex();
    }

    public boolean hasPlaintextColumn() {
        return model().hasPlaintextColumn();
    }

    public boolean hasCiphertextColumn() {
        return model().hasCiphertextColumn();
    }

    public boolean hasCiphertextHeaderColumn() {
        return model().hasCiphertextHeaderColumn();
    }

    public String ciphertextColumnName() {
        return model().getCiphertextColumnName();
    }

    public Type ciphertextColumnType() {
        return model().getCiphertextColumnType();
    }

    public int ciphertextColumnIndex() {
        return model().getCiphertextColumnIndex();
    }

    public String ciphertextHeaderColumnName() {
        return model().getCiphertextHeaderColumnName();
    }

    public Type ciphertextHeaderColumnType() {
        return model().getCiphertextHeaderColumnType();
    }

    public int ciphertextHeaderColumnIndex() {
        return model().getCiphertextHeaderColumnIndex();
    }

    public AttributeConverter<Object, byte[]> bytesConverter() {
        return model().getBytesConverter();
    }

    public AttributeConverter<Object, Object> columnConverter() {
        return model().getColumnConverter();
    }

    @Override
    public String toString() {
        return toSimpleString(this) + "{" + model() + "}";
    }
}
