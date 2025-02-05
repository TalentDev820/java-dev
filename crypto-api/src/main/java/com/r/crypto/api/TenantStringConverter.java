package com.r.crypto.api;

public class TenantStringConverter implements TenantConverter<String> {
    @Override
    public String getTenantName(String tenantObject) {
        return String.valueOf(tenantObject);
    }

    @Override
    public String toTenantObject(String tenantObjectString) {
        return tenantObjectString;
    }
}
