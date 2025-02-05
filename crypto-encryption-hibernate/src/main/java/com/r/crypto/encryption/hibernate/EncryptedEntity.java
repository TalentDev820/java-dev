package com.r.crypto.encryption.hibernate;

import com.r.crypto.api.TenantStringConverter;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Retention(RUNTIME)
@Target(TYPE)
public @interface EncryptedEntity {
    String tenantField() default "";
    String lastModifiedDateField() default "";
    String encryptionJobIdField() default "";
    Class<?> tenantConverter() default TenantStringConverter.class;
}
