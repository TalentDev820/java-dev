package com.r.crypto.api.option;

import com.r.crypto.api.Cryptotext;

import static com.r.crypto.util.Util.quote;

public class TenantOption extends CryptoOption {
    private final String tenant;

    public TenantOption(String tenant) {
        this.tenant = tenant;
    }

    public String getTenant() {
        return tenant;
    }

    public static String findTenant(CryptoOption... options) {
        TenantOption tenantOption = CryptoOption.findOption(TenantOption.class, options);
        return tenantOption == null ? null : tenantOption.getTenant();
    }

    public static String resolveTenant(Cryptotext cryptotext, CryptoOption... options) {
        String optionsTenant = findTenant(options);
        if (cryptotext == null) {
            return optionsTenant;
        }

        String cryptotextTenant = cryptotext.getOption("tenant");
        if (cryptotextTenant == null && optionsTenant == null) {
            return null;
        } else if (cryptotextTenant != null && optionsTenant == null) {
            return cryptotextTenant;
        } else if (cryptotextTenant == null) {
            return optionsTenant;
        } else if (cryptotextTenant.equals(optionsTenant)) {
            return cryptotextTenant;
        } else {
            throw new IllegalStateException("cryptotext tenant=" + cryptotextTenant + " does not match options tenant=" + optionsTenant);
        }
    }

    public static CryptoOption[] assertTenant(Cryptotext cryptotext, CryptoOption... options) {
        String cryptotextTenant = cryptotext.getTenant();
        if (cryptotextTenant == null) {
            return options;
        }

        String optionsTenant = findTenant(options);
        if (optionsTenant == null) {
            CryptoOption[] result = new CryptoOption[options.length + 1];
            System.arraycopy(options, 0, result, 0, options.length);
            result[options.length] = new TenantOption(cryptotextTenant);
            return result;
        }

        if (!cryptotextTenant.equals(optionsTenant)) {
            throw new IllegalStateException("cryptotext tenant=" + cryptotextTenant + " does not match options tenant=" + optionsTenant);
        }

        return options;
    }

    public static TenantOption valueOf(String tenant) {
        return tenant == null ? null : new TenantOption(tenant);
    }

    @Override
    public String toString() {
        return "TenantOption{tenant=" + quote(tenant) + "}";
    }
}
