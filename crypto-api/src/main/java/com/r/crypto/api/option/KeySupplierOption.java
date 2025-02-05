package com.r.crypto.api.option;

import java.security.Key;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

public class KeySupplierOption extends CryptoOption {
    private final Supplier<Key> keySupplier;

    public KeySupplierOption(Supplier<Key> keySupplier) {
        this.keySupplier = requireNonNull(keySupplier);
    }

    public Supplier<Key> getKeySupplier() {
        return keySupplier;
    }

    public static Supplier<Key> findKeySupplier(CryptoOption... options) {
        KeySupplierOption supplierOption = CryptoOption.findOption(KeySupplierOption.class, options);
        return supplierOption == null ? null : supplierOption.getKeySupplier();
    }
}
