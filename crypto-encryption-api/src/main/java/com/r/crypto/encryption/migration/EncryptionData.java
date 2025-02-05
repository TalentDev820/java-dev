package com.r.crypto.encryption.migration;

import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.option.CryptoOption;

import java.util.Arrays;

import static com.r.crypto.util.Util.mask;
import static com.r.crypto.util.Util.quote;

public class EncryptionData {
    private final String id;
    private final MigrationMode mode;
    private final String virtualKey;
    private final CryptoOption[] options;
    private byte[] plaintext;
    private Cryptotext cryptotext;
    private boolean modified;

    public EncryptionData(
            String id,
            MigrationMode mode,
            String virtualKey,
            byte[] plaintext,
            Cryptotext cryptotext,
            CryptoOption... options
    ) {
        this.id = id;
        this.mode = mode;
        this.virtualKey = virtualKey;
        this.plaintext = plaintext;
        this.cryptotext = cryptotext;
        this.options = options;
    }

    public String getId() {
        return id;
    }

    public MigrationMode getMode() {
        return mode;
    }

    public String getVirtualKey() {
        return virtualKey;
    }

    public byte[] getPlaintext() {
        return plaintext;
    }

    public void setPlaintext(byte[] plaintext) {
        this.plaintext = plaintext;
        this.modified = true;
    }

    public Cryptotext getCryptotext() {
        return cryptotext;
    }

    public void setCryptotext(Cryptotext cryptotext) {
        this.cryptotext = cryptotext;
        this.modified = true;
    }

    public boolean isModified() {
        return modified;
    }

    public void setModified(boolean modified) {
        this.modified = modified;
    }

    public CryptoOption[] getOptions() {
        return options;
    }

    public boolean hasPlaintext() {
        return plaintext != null;
    }

    public boolean hasCryptotext() {
        return cryptotext != null;
    }

    public boolean plaintextOnly() {
        return hasPlaintext() && !hasCryptotext();
    }

    public boolean cryptotextOnly() {
        return !hasPlaintext() && hasCryptotext();
    }

    public boolean bothSet() {
        return hasPlaintext() && hasCryptotext();
    }

    @Override
    public String toString() {
        return "EncryptionData{"
                + "id=" + quote(id)
                + ", mode=" + mode
                + ", virtualKey=" + quote(virtualKey)
                + ", options=" + Arrays.toString(options)
                + ", plaintext=" + mask(plaintext)
                + ", cryptotext=" + cryptotext
                + ", modified=" + modified
                + "}";
    }
}
