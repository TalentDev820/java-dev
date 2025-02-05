package com.r.crypto.encryption.api;

import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.batch.BatchItem;
import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.api.option.CryptoOption;

import static com.r.crypto.encryption.api.EncryptionOperation.DECRYPT;
import static com.r.crypto.encryption.api.EncryptionOperation.ENCRYPT;
import static com.r.crypto.encryption.api.EncryptionOperation.REWRAP;

public class EncryptionItem extends BatchItem<EncryptionOperation> {
    private byte[] plaintext;
    private Cryptotext cryptotext;

    public EncryptionItem(String virtualKey, byte[] plaintext, CryptoOption... options) {
        super(ENCRYPT, options);
        this.virtualKey = virtualKey;
        this.plaintext = plaintext;
    }

    public EncryptionItem(Cryptotext cryptotext, CryptoOption... options) {
        super(DECRYPT, options);
        this.cryptotext = cryptotext;
        this.kmsKey = cryptotext == null ? null : cryptotext.getKey();
    }

    public EncryptionItem(Cryptotext cryptotext, KmsKey kmsKey, CryptoOption... options) {
        super(REWRAP, options);
        this.cryptotext = cryptotext;
        this.kmsKey = kmsKey;
    }

    public byte[] getPlaintext() {
        return plaintext;
    }

    public void setPlaintext(byte[] plaintext) {
        this.plaintext = plaintext;
    }

    public Cryptotext getCryptotext() {
        return cryptotext;
    }

    public void setCryptotext(Cryptotext cryptotext) {
        this.cryptotext = cryptotext;
    }
}
