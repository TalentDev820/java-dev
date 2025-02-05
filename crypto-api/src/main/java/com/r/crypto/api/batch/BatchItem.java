package com.r.crypto.api.batch;

import com.r.crypto.api.CryptoOperation;
import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.exception.RCryptoException;

import java.util.ArrayList;
import java.util.List;

import static java.util.Arrays.asList;

public abstract class BatchItem<O extends CryptoOperation> {
    protected final List<CryptoOption> options = new ArrayList<>();
    protected O operation;
    protected String virtualKey;
    protected KmsKey kmsKey;
    protected boolean processed;
    protected boolean successful;
    protected RCryptoException exception;

    protected BatchItem(O operation, CryptoOption... options) {
        this.operation = operation;
        this.options.addAll(asList(options));
    }

    public O getOperation() {
        return operation;
    }

    public void setOperation(O operation) {
        this.operation = operation;
    }

    public String getVirtualKey() {
        return virtualKey;
    }

    public void setVirtualKey(String virtualKey) {
        this.virtualKey = virtualKey;
    }

    public void setKmsKey(KmsKey kmsKey) {
        this.kmsKey = kmsKey;
    }

    public KmsKey getKmsKey() {
        return kmsKey;
    }

    public CryptoOption[] getOptions() {
        return options.toArray(new CryptoOption[0]);
    }

    public void setOptions(CryptoOption[] options) {
        this.options.clear();
        this.options.addAll(asList(options));
    }

    public void addOption(CryptoOption option) {
        this.options.add(option);
    }

    public boolean processed() {
        return processed;
    }

    public void setProcessed(boolean processed) {
        this.processed = processed;
    }

    public boolean successful() {
        return successful;
    }

    public void setSuccessful() {
        this.processed = true;
        this.successful = true;
        this.exception = null;
    }

    public RCryptoException getException() {
        return exception;
    }

    public void setException(RCryptoException e) {
        this.processed = true;
        this.successful = false;
        this.exception = e;
    }
}
