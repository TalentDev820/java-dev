package com.r.crypto.encryption.api.service;

import com.r.crypto.api.CryptoAlgorithm;
import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.api.service.CryptoService;
import com.r.crypto.encryption.api.EncryptionItem;
import com.r.crypto.encryption.exception.RCryptoEncryptionException;

import java.security.Key;
import java.util.Collection;

public interface EncryptionService extends CryptoService {
    Cryptotext encrypt(byte[] plaintext, String virtualKey, CryptoOption... options) throws RCryptoEncryptionException;

    Cryptotext encrypt(byte[] plaintext, Key key, CryptoOption... options) throws RCryptoEncryptionException;

    Cryptotext encrypt(byte[] plaintext, Key key, CryptoAlgorithm algorithm, CryptoOption... options) throws RCryptoEncryptionException;

    byte[] decrypt(Cryptotext cryptotext, CryptoOption... options) throws RCryptoEncryptionException;

    byte[] decrypt(byte[] cryptotextData, String virtualKey, CryptoOption... options) throws RCryptoEncryptionException;

    byte[] decrypt(byte[] cryptotextData, Key key, CryptoOption... options) throws RCryptoEncryptionException;

    byte[] decrypt(byte[] cryptotextData, Key key, CryptoAlgorithm algorithm, CryptoOption... options) throws RCryptoEncryptionException;

    Cryptotext rewrap(Cryptotext cryptotext, CryptoOption... options);

    boolean process(Collection<EncryptionItem> items, boolean batch);

    void rotateKey(String virtualKey, CryptoOption... options);
}
