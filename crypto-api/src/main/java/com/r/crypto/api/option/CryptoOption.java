package com.r.crypto.api.option;

import java.util.Arrays;

public class CryptoOption {
    public static <T extends CryptoOption> T findOption(Class<T> cls, CryptoOption... options) {
        if (cls == null || options == null) {
            return null;
        }

        return Arrays.stream(options)
                .filter(cls::isInstance)
                .map(cls::cast)
                .findFirst().orElse(null);
    }
}
