package com.r.crypto.encryption.api.provider;

import com.r.crypto.api.CryptoAlgorithm;
import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.api.provider.CryptoProvider;
import com.r.crypto.encryption.exception.RCryptoEncryptionException;

/**
 * Interface for encyption/decryption providers.
 *
 * @param <K> the type of key used for encryption
 */
public interface EncryptionProvider<K> extends CryptoProvider {
    Cryptotext encrypt(byte[] plaintext, CryptoAlgorithm algorithm, K key, CryptoOption... options) throws RCryptoEncryptionException;

    /** Service layer can call this for asymmetric ciphers after looking up cert */
    byte[] decrypt(Cryptotext cryptotext, K key, CryptoOption... options) throws RCryptoEncryptionException;
}
