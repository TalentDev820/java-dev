package com.r.crypto.encryption.api.provider;

import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.api.provider.RemoteCryptoProvider;
import com.r.crypto.encryption.api.EncryptionItem;
import com.r.crypto.encryption.exception.RCryptoEncryptionException;
import com.r.crypto.exception.RCryptoException;

import java.util.List;

public interface RemoteEncryptionProvider extends RemoteCryptoProvider, EncryptionProvider<KmsKey> {
    default Cryptotext encrypt(byte[] plaintext, KmsKey key, CryptoOption... options) throws RCryptoEncryptionException {
        return encrypt(plaintext, null, key, options);
    }

    default byte[] decrypt(Cryptotext cryptotext, CryptoOption... options) throws RCryptoEncryptionException {
        return decrypt(cryptotext, null, options);
    }

    default Cryptotext rewrap(Cryptotext cryptotext, CryptoOption... options) throws RCryptoEncryptionException {
        return encrypt(decrypt(cryptotext, options), cryptotext.getKey(), options);
    }

    default boolean process(List<EncryptionItem> items, boolean batch) {
        boolean success = true;

        for (EncryptionItem item : items) {
            KmsKey kmsKey = item.getKmsKey();
            byte[] plaintext = item.getPlaintext();
            Cryptotext cryptotext = item.getCryptotext();
            CryptoOption[] options = item.getOptions();

            try {
                switch (item.getOperation()) {
                    case ENCRYPT:
                        item.setCryptotext(encrypt(plaintext, kmsKey, options));
                        break;
                    case DECRYPT:
                        item.setPlaintext(decrypt(cryptotext, kmsKey, options));
                        break;
                    case REWRAP:
                        item.setCryptotext(encrypt(decrypt(cryptotext, options), kmsKey, options));
                        break;
                    default:
                        throw new UnsupportedOperationException("unknown operation=" + item.getOperation());
                }
                item.setSuccessful();
            } catch (RCryptoException e) {
                item.setException(e);
                success = false;
            } catch (Throwable t) {
                RCryptoEncryptionException error = new RCryptoEncryptionException(t);
                item.setException(error);
                throw error;
            }
        }

        return success;
    }
}
