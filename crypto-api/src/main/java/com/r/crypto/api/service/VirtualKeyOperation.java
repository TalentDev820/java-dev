package com.r.crypto.api.service;

import com.r.crypto.api.CryptoAlgorithm;
import com.r.crypto.api.CryptoOperation;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.api.provider.RemoteCryptoProvider;

import java.util.ArrayList;
import java.util.List;

import static com.r.crypto.util.Util.quote;
import static com.r.crypto.util.Util.toSimpleString;
import static java.util.Arrays.asList;

public class VirtualKeyOperation<O extends CryptoOperation, R extends RemoteCryptoProvider> {
    private final CryptoAlgorithm algorithm;
    private final O operation;
    private final R provider;
    private final String kmsKeyName;
    private final List<CryptoOption> options = new ArrayList<>();

    public VirtualKeyOperation(
            CryptoAlgorithm algorithm,
            O operation,
            R provider,
            String kmsKeyName,
            CryptoOption... options
    ) {
        this.algorithm = algorithm;
        this.operation = operation;
        this.provider = provider;
        this.kmsKeyName = kmsKeyName;
        this.options.addAll(asList(options));
    }

    public CryptoAlgorithm getAlgorithm() {
        return algorithm;
    }

    public O getOperation() {
        return operation;
    }

    public R getProvider() {
        return provider;
    }

    public String getKmsKeyName() {
        return kmsKeyName;
    }

    public List<CryptoOption> getOptions() {
        return options;
    }

    @Override
    public String toString() {
        return toSimpleString(this) + "{"
                + "operation=" + operation
                + ", algorithm=" + algorithm
                + ", kmsKeyName=" + quote(kmsKeyName)
                + ", provider=" + toSimpleString(provider)
                + ", options=" + options
                + "}";
    }
}
