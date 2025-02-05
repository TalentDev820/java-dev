package com.r.crypto.api;

public interface TenantConverter<T> {
    String getTenantName(T tenantObject);

    T toTenantObject(String tenantObjectString);
}
