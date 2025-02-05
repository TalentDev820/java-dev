package com.r.crypto.service.encryption.impl.vault;

import static com.r.crypto.api.option.TenantOption.findTenant;
import static com.r.crypto.api.option.TenantOption.resolveTenant;
import static com.r.crypto.encryption.api.EncryptionOperation.DECRYPT;
import static com.r.crypto.encryption.api.EncryptionOperation.ENCRYPT;
import static com.r.crypto.encryption.api.EncryptionOperation.REWRAP;
import static com.r.crypto.util.Util.list;
import static com.r.crypto.util.Util.quote;
import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.toList;
import static org.slf4j.event.Level.INFO;

import com.r.crypto.api.CryptoAlgorithm;
import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.batch.BatchItem;
import com.r.crypto.api.kms.ExportedKey;
import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.api.option.TenantOption;
import com.r.crypto.encryption.api.EncryptionItem;
import com.r.crypto.encryption.api.EncryptionOperation;
import com.r.crypto.encryption.api.provider.RemoteEncryptionProvider;
import com.r.crypto.encryption.exception.RCryptoEncryptionException;
import com.r.crypto.exception.RCryptoInvalidKeyException;
import com.r.crypto.exception.RCryptoMissingKeyException;
import com.r.crypto.util.Timer;
import com.r.crypto.util.Timer.TimedResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.vault.authentication.SessionManager;
import org.springframework.vault.client.VaultEndpointProvider;
import org.springframework.vault.core.VaultTransitOperations;
import org.springframework.vault.support.Ciphertext;
import org.springframework.vault.support.Plaintext;
import org.springframework.vault.support.RawTransitKey;
import org.springframework.vault.support.TransitKeyType;
import org.springframework.vault.support.VaultDecryptionResult;
import org.springframework.vault.support.VaultEncryptionResult;
import org.springframework.vault.support.VaultTransitKey;

import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class VaultAesEncryptionProvider extends VaultProvider implements RemoteEncryptionProvider {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final Timer timer = new Timer(logger, INFO, RCryptoEncryptionException.class);

    protected static final String DEFAULT_ALGORITHM = "aes";
    protected static final String VAULT_AES_ALGORITHM_TYPE = "aes256-gcm96";

    /**
     * Constructor
     * @param endpointProvider VaultEndpointProvider for VaultTemplate
     * @param requestFactory ClientHttpRequestFactory for VaultTemplate
     * @param sessionManager SessionManager for VaultTemplate
     * @param retryTemplate for retries, if null defaults to a single attempt
     * @param basePath Vault Transit path
     */
    public VaultAesEncryptionProvider(
            VaultEndpointProvider endpointProvider,
            ClientHttpRequestFactory requestFactory,
            SessionManager sessionManager,
            RetryTemplate retryTemplate,
            String basePath
    ) {
        super(endpointProvider, requestFactory, sessionManager, retryTemplate, basePath);
    }

    public VaultAesEncryptionProvider(
            VaultEndpointProvider endpointProvider,
            ClientHttpRequestFactory requestFactory,
            SessionManager sessionManager,
            String basePath
    ) {
        this(endpointProvider, requestFactory, sessionManager, null, basePath);
    }

    @Override
    public Cryptotext encrypt(byte[] plaintext, CryptoAlgorithm algorithm, KmsKey kmsKey, CryptoOption... options) {
        if (plaintext == null) {
            return null;
        }

        return timer.timedResult(
                () -> "encrypt kmsKey=" + quote(kmsKey) + " options=" + list(options),
                () -> {
                    requireNonNull(kmsKey);
                    if (algorithm != null && !algorithm.matches("aes[gcm,128,96]")) {
                        throw new RCryptoEncryptionException("unsupported algorithm=" + algorithm);
                    }

                    String keyName = kmsKey.getName();
                    VaultTransitOperations transit = transit(TenantOption.findTenant(options));
                    Ciphertext ciphertext = retry.execute(context -> transit.encrypt(keyName, Plaintext.of(plaintext)));
                    Cryptotext cryptotext = toCryptotext(ciphertext, keyName, DEFAULT_ALGORITHM, options);
                    return new TimedResult<>(cryptotext, () -> "result=" + cryptotext.toSimpleString());
                }
        );
    }

    @Override
    public byte[] decrypt(Cryptotext cryptotext, KmsKey key, CryptoOption... options) {
        if (cryptotext == null) {
            return null;
        }

        return timer.time(
                () -> "decrypt cryptotext=" + cryptotext.toSimpleString()
                        + " kmsKey=" + quote(key)
                        + " options=" + list(options),
                () -> {
                    KmsKey kmsKey = requireNonNull(KmsKey.resolveKey(cryptotext, key));
                    CryptoOption[] resolvedOptions = TenantOption.assertTenant(cryptotext, options);
                    VaultTransitOperations transit = transit(resolveTenant(cryptotext, resolvedOptions));
                    Ciphertext ciphertext = toVaultCiphertext(cryptotext, kmsKey);
                    Plaintext plaintext = retry.execute(context -> transit.decrypt(kmsKey.getName(), ciphertext));
                    return plaintext.getPlaintext();
                }
        );
    }

    @Override
    public Integer getActiveVersion(String kmsKeyName, CryptoOption... options) {
        return timer.time(
                INFO,
                "getActiveVersion kmsKeyName=" + quote(kmsKeyName) + " options=" + list(options),
                () -> requireNonNull(transit(findTenant(options)).getKey(kmsKeyName)).getLatestVersion()
        );
    }

    @Override
    public ExportedKey exportKey(KmsKey kmsKey, CryptoOption... options) {
        return timer.time(INFO, "exportKey kmsKey=" + quote(kmsKey) + " options=" + list(options), () -> {
            VaultTransitOperations transit = transit(findTenant(options));

            // confirm that the key exists and has the expected type
            VaultTransitKey vaultKey = transit.getKey(kmsKey.getName());
            if (vaultKey == null) {
                throw new RCryptoMissingKeyException(kmsKey + " not found in vault");
            }
            String keyType = vaultKey.getType();
            if (!keyType.equals(VAULT_AES_ALGORITHM_TYPE)) {
                throw new RCryptoInvalidKeyException(kmsKey + " type=" + keyType + " expectedType=" + VAULT_AES_ALGORITHM_TYPE);
            }

            RawTransitKey rawKey = requireNonNull(transit.exportKey(kmsKey.getName(), TransitKeyType.ENCRYPTION_KEY));
            final int keyVersion;
            if (kmsKey.getVersion() != null) {
                keyVersion = kmsKey.getVersion();
            } else {
                keyVersion = rawKey.getKeys().keySet().stream()
                        .map(Integer::parseInt)
                        .max(Integer::compareTo)
                        .orElseThrow(() -> new RCryptoInvalidKeyException("no versioned keys for " + kmsKey));
            }
            byte[] keyBytes = VAULT_DECODER.decode(rawKey.getKeys().get(String.valueOf(keyVersion)));

            return new ExportedKey(
                    new KmsKey(kmsKey.getName(), keyVersion),
                    new SecretKeySpec(keyBytes, "AES")
            );
        });
    }

    @Override
    public void rotateKey(String kmsKeyName, CryptoOption... options) {
        timer.time(
                INFO,
                "rotateKey kmsKeyName=" + quote(kmsKeyName) + " options=" + list(options),
                () -> transit(findTenant(options)).rotate(kmsKeyName)
        );
    }

    @Override
    public Cryptotext rewrap(Cryptotext cryptotext, CryptoOption... options) {
        if (cryptotext == null) {
            return null;
        }

        return timer.time(
                INFO,
                "rewrap cryptotext=" + cryptotext.toSimpleString() + " options=" + list(options),
                () -> {
                    KmsKey kmsKey = requireNonNull(cryptotext.getKey());
                    RVaultTransitTemplate transit = transit(resolveTenant(cryptotext, options));
                    Ciphertext vaultCiphertext = toVaultCiphertext(cryptotext);
                    String result = transit.rewrap(kmsKey.getName(), vaultCiphertext.getCiphertext());
                    return toCryptotext(result, kmsKey.getName(), DEFAULT_ALGORITHM, options);
                }
        );
    }

    @Override
    public boolean process(List<EncryptionItem> encryptionItems, boolean batch) {
        if (!batch) {
            return RemoteEncryptionProvider.super.process(encryptionItems, false);
        }

        Map<EncryptionOperation, Map<String, Map<String, List<EncryptionItem>>>> results = new HashMap<>();

        encryptionItems.stream()
                .filter(item -> !item.processed())
                .forEach(item ->
                        results.computeIfAbsent(item.getOperation(), o -> new HashMap<>())
                                .computeIfAbsent(item.getKmsKey().getName(), k -> new HashMap<>())
                                .computeIfAbsent(findTenant(item.getOptions()), t -> new ArrayList<>()).add(item)
                );

        if (results.containsKey(REWRAP)) {
            results.get(REWRAP).forEach((kmsKeyName, tenantToItemsMap) ->
                    tenantToItemsMap.forEach((tenant, items) ->
                            items.forEach(item -> {
                                // Is the rewrap for a different key?
                                if (!item.getCryptotext().getKey().getName().equals(kmsKeyName)) {
                                    // Need to decrypt the item first
                                    results.computeIfAbsent(DECRYPT, o -> new HashMap<>())
                                            .computeIfAbsent(item.getCryptotext().getKey().getName(), k -> new HashMap<>())
                                            .computeIfAbsent(tenant, t -> new ArrayList<>()).add(item);
                                    // Then encrypt it
                                    results.computeIfAbsent(ENCRYPT, o -> new HashMap<>())
                                            .computeIfAbsent(kmsKeyName, k -> new HashMap<>())
                                            .computeIfAbsent(tenant, t -> new ArrayList<>()).add(item);
                                }
                            })
                    )
            );
        }

        if (results.containsKey(DECRYPT)) {
            results.get(DECRYPT).forEach((kmsKeyName, tenantToItemsMap) ->
                    tenantToItemsMap.forEach((tenant, items) -> decryptBatch(items, kmsKeyName, TenantOption.valueOf(tenant)))
            );
        }

        if (results.containsKey(ENCRYPT)) {
            results.get(ENCRYPT).forEach((kmsKeyName, tenantToItemsMap) ->
                    tenantToItemsMap.forEach((tenant, items) -> encryptBatch(items, kmsKeyName, TenantOption.valueOf(tenant)))
            );
        }

        if (results.containsKey(REWRAP)) {
            results.get(REWRAP).forEach((kmsKeyName, tenantToItemsMap) ->
                    tenantToItemsMap.forEach((tenant, items) -> rewrapBatch(items, kmsKeyName, TenantOption.valueOf(tenant)))
            );
        }

        return encryptionItems.stream().allMatch(BatchItem<EncryptionOperation>::successful);
    }

    private void decryptBatch(List<EncryptionItem> items, String kmsKeyName, CryptoOption... options) {
        timer.bracketTime("decryptBatch items=%d kmsKey=%s tenant=%s", items.size(), kmsKeyName, findTenant(options), () -> {
            List<Ciphertext> vaultCiphertexts = items.stream()
                    .filter(item -> item.getOperation() == DECRYPT || item.getOperation() == REWRAP)
                    .filter(item -> item.getCryptotext().getKey().getName().equals(kmsKeyName))
                    .map(item -> toVaultCiphertext(item.getCryptotext()))
                    .collect(toList());

            if (vaultCiphertexts.isEmpty()) {
                return;
            }

            VaultTransitOperations transit = transit(findTenant(options));
            List<VaultDecryptionResult> result = retry.execute(context -> transit.decrypt(kmsKeyName, vaultCiphertexts));

            for (int i = 0; i < items.size(); i++) {
                EncryptionItem item = items.get(i);
                Plaintext plaintext = result.get(i).get();
                item.setPlaintext(plaintext == null ? null : plaintext.getPlaintext());
                item.setSuccessful();
            }
        });
    }

    private void encryptBatch(List<EncryptionItem> items, String kmsKeyName, CryptoOption... options) {
        timer.bracketTime("encryptBatch items=%d kmsKey=%s tenant=%s", items.size(), kmsKeyName, findTenant(options), () -> {
            List<Plaintext> vaultPlaintexts = items.stream()
                    .filter(item -> item.getOperation() == ENCRYPT || item.getOperation() == REWRAP)
                    .filter(item -> item.getKmsKey().getName().equals(kmsKeyName))
                    .map(EncryptionItem::getPlaintext)
                    .map(Plaintext::of)
                    .collect(toList());

            if (vaultPlaintexts.isEmpty()) {
                return;
            }

            VaultTransitOperations transit = transit(findTenant(options));
            List<VaultEncryptionResult> result = retry.execute(context -> transit.encrypt(kmsKeyName, vaultPlaintexts));

            for (int i = 0; i < items.size(); i++) {
                EncryptionItem item = items.get(i);
                Ciphertext ciphertext = result.get(i).get();
                item.setCryptotext(toCryptotext(ciphertext, kmsKeyName, DEFAULT_ALGORITHM, options));
                item.setSuccessful();
            }
        });
    }

    private void rewrapBatch(List<EncryptionItem> items, String kmsKeyName, CryptoOption... options) {
        timer.bracketTime("rewrapBatch items=%d kmsKey=%s tenant=%s", items.size(), kmsKeyName, findTenant(options), () -> {
            List<Ciphertext> vaultPlaintexts = items.stream()
                    .filter(item -> !item.processed())
                    .filter(item -> item.getOperation() == REWRAP)
                    .filter(item -> item.getKmsKey().getName().equals(kmsKeyName))
                    .map(item -> toVaultCiphertext(item.getCryptotext(), item.getCryptotext().getKey()))
                    .collect(toList());

            if (vaultPlaintexts.isEmpty()) {
                return;
            }

            RVaultTransitTemplate transit = transit(findTenant(options));
            List<VaultEncryptionResult> result = retry.execute(context -> transit.rewrap(kmsKeyName, vaultPlaintexts));

            for (int i = 0; i < items.size(); i++) {
                EncryptionItem item = items.get(i);
                Ciphertext ciphertext = result.get(i).get();
                item.setCryptotext(toCryptotext(ciphertext, kmsKeyName, DEFAULT_ALGORITHM, options));
                item.setSuccessful();
            }
        });
    }
}
