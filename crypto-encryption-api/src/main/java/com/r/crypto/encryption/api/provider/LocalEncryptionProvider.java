package com.r.crypto.encryption.api.provider;

import java.security.Key;

import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.api.provider.LocalCryptoProvider;
import com.r.crypto.encryption.exception.RCryptoEncryptionException;

public interface LocalEncryptionProvider extends LocalCryptoProvider, EncryptionProvider<Key> {
    Cryptotext encrypt(byte[] plaintext, Key key, CryptoOption... options) throws RCryptoEncryptionException;
}
