package com.r.crypto.encryption.hibernate;

import com.r.crypto.api.TenantConverter;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.metamodel.Attribute;
import javax.persistence.metamodel.EntityType;
import java.lang.reflect.Field;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static com.r.crypto.util.ExceptionWrapper.wrap;
import static com.r.crypto.util.Util.cast;
import static com.r.crypto.util.Util.toSimpleString;
import static java.util.Arrays.asList;
import static java.util.Objects.requireNonNull;

public class EncryptedEntityModel {
    private final Class<?> entityClass;
    private final String entityTypeName;
    private final Field idField;
    private final Field tenantField;
    private final Field encryptionJobIdField;
    private final TenantConverter<Object> tenantConverter;
    private final String idFieldName;
    private final String versionFieldName;
    private final String modifiedDateFieldName;
    private final String encryptionJobIdFieldName;
    private final String encryptionJobIdColumnName;
    private final Map<String, EncryptedTypeModel> typeModelsMap = new HashMap<>();
    private final Map<Field, Set<CascadeType>> associationCascades = new HashMap<>();

    public static EncryptedEntityModel create(EntityType<?> entityType) {
        Class<?> entityClass = entityType.getJavaType();
        if (entityClass.getAnnotation(EncryptedEntity.class) == null) {
            return null;
        } else {
            return new EncryptedEntityModel(entityType);
        }
    }

    private EncryptedEntityModel(EntityType<?> entityType) {
        this.entityClass = entityType.getJavaType();
        this.entityTypeName = entityType.getName();

        if (entityType.hasSingleIdAttribute()) {
            this.idField = (Field) entityType.getId(entityType.getIdType().getJavaType()).getJavaMember();
            this.idFieldName = idField.getName();
        } else {
            this.idField = null;
            this.idFieldName = null;
        }

        if (entityType.hasVersionAttribute()) {
            Field versionField = (Field) entityType.getVersion(Short.class).getJavaMember();
            this.versionFieldName = versionField.getName();
        } else {
            this.versionFieldName = null;
        }

        EncryptedEntity encryptedEntity = entityClass.getAnnotation(EncryptedEntity.class);
        if (encryptedEntity.lastModifiedDateField().isEmpty()) {
            this.modifiedDateFieldName = null;
        } else {
            this.modifiedDateFieldName = encryptedEntity.lastModifiedDateField();
        }

        if (encryptedEntity.encryptionJobIdField().isEmpty()) {
            this.encryptionJobIdField = null;
            this.encryptionJobIdFieldName = null;
            this.encryptionJobIdColumnName = null;
        } else {
            this.encryptionJobIdField = (Field) entityType.getAttribute(encryptedEntity.encryptionJobIdField()).getJavaMember();
            this.encryptionJobIdFieldName = encryptedEntity.encryptionJobIdField();
            this.encryptionJobIdColumnName = encryptionJobIdField.getAnnotation(Column.class).name();
        }

        if (encryptedEntity.tenantField().isEmpty()) {
            this.tenantField = null;
            this.tenantConverter = null;
        } else {
            this.tenantField = (Field) entityType.getAttribute(encryptedEntity.tenantField()).getJavaMember();
            requireNonNull(this.tenantField, "tenantField " + encryptedEntity.tenantField() + " not found in " + entityClass);
            this.tenantField.setAccessible(true);
            this.tenantConverter = wrap(() ->
              cast(encryptedEntity.tenantConverter().getDeclaredConstructor().newInstance())
            );
        }

        for (Attribute<?, ?> attribute : entityType.getAttributes()) {
            if (EncryptedObject.class.isAssignableFrom(attribute.getJavaType())) {
                EncryptedTypeModel typeModel = EncryptedType.getTypeModel(entityClass, attribute.getName());
                typeModel.setEntityModel(this);
                typeModelsMap.put(attribute.getName(), typeModel);
            } else if (attribute.isAssociation()) {
                CascadeType[] cascadeTypes;
                Field field = (Field) attribute.getJavaMember();
                field.setAccessible(true);
                switch (attribute.getPersistentAttributeType()) {
                    case ONE_TO_ONE:
                        cascadeTypes = field.getAnnotation(OneToOne.class).cascade();
                        break;
                    case ONE_TO_MANY:
                        cascadeTypes = field.getAnnotation(OneToMany.class).cascade();
                        break;
                    case MANY_TO_ONE:
                        cascadeTypes = field.getAnnotation(ManyToOne.class).cascade();
                        break;
                    case MANY_TO_MANY:
                        cascadeTypes = field.getAnnotation(ManyToMany.class).cascade();
                        break;
                    default:
                        continue;
                }
                associationCascades.put(field, new HashSet<>(asList(cascadeTypes)));
            }
        }
    }

    public Map<Field, Set<CascadeType>> getAssociationCascades() {
        return associationCascades;
    }

    public Class<?> getEntityClass() {
        return entityClass;
    }

    public String getEntityTypeName() {
        return entityTypeName;
    }

    public String getIdFieldName() {
        return idFieldName;
    }

    public Long getId(Object entity) {
        return wrap(() -> (Long) idField.get(entity));
    }

    public String getVersionFieldName() {
        return versionFieldName;
    }

    public String getModifiedDateFieldName() {
        return modifiedDateFieldName;
    }

    public Field getTenantField() {
        return tenantField;
    }

    public String getTenantFieldName() {
        return tenantField.getName();
    }

    public String getTenant(Object entity) {
        return tenantField == null
                ? null
                : wrap(() -> tenantConverter.getTenantName(tenantField.get(entity)));
    }

    public TenantConverter<Object> getTenantConverter() {
        return tenantConverter;
    }

    public Collection<EncryptedTypeModel> getTypeModels() {
        return typeModelsMap.values();
    }

    public String getEncryptionJobIdFieldName() {
        return encryptionJobIdFieldName;
    }

    public Field getEncryptionJobIdField() {
        return encryptionJobIdField;
    }

    public String getEncryptionJobIdColumnName() {
        return encryptionJobIdColumnName;
    }

    @Override
    public String toString() {
        String tenantFieldString = null;
        if (tenantField != null) {
            if (tenantField.getDeclaringClass() == entityClass) {
                tenantFieldString = tenantField.getName();
            } else {
                tenantFieldString = tenantField.getDeclaringClass().getSimpleName() + "." + tenantField.getName();
            }
            tenantFieldString += ", tenantConverter=" + tenantConverter.getClass().getSimpleName();
        }

        return toSimpleString(this) + "{"
                + "class=" + entityClass.getSimpleName()
                + ", entityTypeName=" + entityTypeName
                + ", idField=" + idFieldName
                + ", modifiedDateField=" + modifiedDateFieldName
                + ", encryptionJobIdField=" + encryptionJobIdFieldName
                + ", tenantField=" + tenantFieldString
                + ", tenantConverter=" + (tenantConverter == null ? null : tenantConverter.getClass().getName())
                + ", types=" + typeModelsMap
                + "}";
    }
}
