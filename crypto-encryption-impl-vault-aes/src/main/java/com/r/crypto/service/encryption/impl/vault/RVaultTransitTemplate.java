package com.r.crypto.service.encryption.impl.vault;

import org.springframework.util.Assert;
import org.springframework.util.Base64Utils;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.vault.VaultException;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.core.VaultTransitOperations;
import org.springframework.vault.core.VaultTransitTemplate;
import org.springframework.vault.support.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

// This class is a modified copy of Spring's original VaultTransitTemplate,
// with a couple tweaks including prefixing the key name for multitenancy,
// and adding the rewrap() method. To make it easier to compare to the
// original file, we retain the formatting and thus disable checkstyle.
// CHECKSTYLE:OFF
@SuppressWarnings("NullableProblems") // due to the original file
public class RVaultTransitTemplate implements VaultTransitOperations {
    public static final String KEY_PREFIX_SEPARATOR = "_";

    private final VaultOperations vaultOperations;
    private final VaultTransitTemplate transit;
    private final String path;
    private final String tenantKeyPrefix;

    public RVaultTransitTemplate(VaultOperations vaultOperations, String path, String tenant) {
        this.vaultOperations = vaultOperations;
        this.transit = new VaultTransitTemplate(this.vaultOperations, path);
        this.path = path;
        this.tenantKeyPrefix = tenant == null ? "" : tenant + KEY_PREFIX_SEPARATOR;
    }

    public List<VaultEncryptionResult> rewrap(String keyName, List<Ciphertext> batchRequest) {
        Assert.hasText(keyName, "KeyName must not be empty");
        Assert.notEmpty(batchRequest, "BatchRequest must not be null and must have at least one entry");

        List<Map<String, String>> batch = new ArrayList<>(batchRequest.size());

        for (Ciphertext request : batchRequest) {
            Map<String, String> vaultRequest = new LinkedHashMap<>(2);
            vaultRequest.put("ciphertext", request.getCiphertext());
            if (request.getContext() != null) {
                applyTransitOptions(request.getContext(), vaultRequest);
            }

            batch.add(vaultRequest);
        }

        VaultResponse vaultResponse = vaultOperations.write(
                String.format("%s/rewrap/%s", path, tenantKeyPrefix + keyName),
                Collections.singletonMap("batch_input", batch)
        );

        return toRewrapResults(vaultResponse, batchRequest);
    }

    @Override
    public void createKey(String keyName) {
        transit.createKey(tenantKeyPrefix + keyName);
    }

    @Override
    public void createKey(String keyName, VaultTransitKeyCreationRequest createKeyRequest) {
        transit.createKey(tenantKeyPrefix + keyName, createKeyRequest);
    }

    @Override
    public List<String> getKeys() {
        return transit.getKeys();
    }

    @Override
    public void configureKey(String keyName, VaultTransitKeyConfiguration keyConfiguration) {
        transit.configureKey(tenantKeyPrefix + keyName, keyConfiguration);
    }

    @Override
    public RawTransitKey exportKey(String keyName, TransitKeyType type) {
        return transit.exportKey(tenantKeyPrefix + keyName, type);
    }

    @Override
    public VaultTransitKey getKey(String keyName) {
        return transit.getKey(tenantKeyPrefix + keyName);
    }

    @Override
    public void deleteKey(String keyName) {
        transit.deleteKey(tenantKeyPrefix + keyName);
    }

    @Override
    public void rotate(String keyName) {
        transit.rotate(tenantKeyPrefix + keyName);
    }

    @Override
    public String encrypt(String keyName, String plaintext) {
        return transit.encrypt(tenantKeyPrefix + keyName, plaintext);
    }

    @Override
    public Ciphertext encrypt(String keyName, Plaintext plaintext) {
        return transit.encrypt(tenantKeyPrefix + keyName, plaintext);
    }

    @Override
    public String encrypt(String keyName, byte[] plaintext, VaultTransitContext transitRequest) {
        return transit.encrypt(tenantKeyPrefix + keyName, plaintext, transitRequest);
    }

    @Override
    public List<VaultEncryptionResult> encrypt(String keyName, List<Plaintext> batchRequest) {
        return transit.encrypt(tenantKeyPrefix + keyName, batchRequest);
    }

    @Override
    public String decrypt(String keyName, String ciphertext) {
        return transit.decrypt(tenantKeyPrefix + keyName, ciphertext);
    }

    @Override
    public Plaintext decrypt(String keyName, Ciphertext ciphertext) {
        return transit.decrypt(tenantKeyPrefix + keyName, ciphertext);
    }

    @Override
    public byte[] decrypt(String keyName, String ciphertext, VaultTransitContext transitContext) {
        return transit.decrypt(tenantKeyPrefix + keyName, ciphertext, transitContext);
    }

    @Override
    public List<VaultDecryptionResult> decrypt(String keyName, List<Ciphertext> batchRequest) {
        return transit.decrypt(tenantKeyPrefix + keyName, batchRequest);
    }

    @Override
    public String rewrap(String keyName, String ciphertext) {
        return transit.rewrap(tenantKeyPrefix + keyName, ciphertext);
    }

    @Override
    public String rewrap(String keyName, String ciphertext, VaultTransitContext transitContext) {
        return transit.rewrap(tenantKeyPrefix + keyName, ciphertext, transitContext);
    }

    @Override
    public Hmac getHmac(String keyName, Plaintext plaintext) {
        return transit.getHmac(tenantKeyPrefix + keyName, plaintext);
    }

    @Override
    public Hmac getHmac(String keyName, VaultHmacRequest request) {
        return transit.getHmac(tenantKeyPrefix + keyName, request);
    }

    @Override
    public Signature sign(String keyName, Plaintext plaintext) {
        return transit.sign(tenantKeyPrefix + keyName, plaintext);
    }

    @Override
    public Signature sign(String keyName, VaultSignRequest request) {
        return transit.sign(tenantKeyPrefix + keyName, request);
    }

    @Override
    public boolean verify(String keyName, Plaintext plaintext, Signature signature) {
        return transit.verify(tenantKeyPrefix + keyName, plaintext, signature);
    }

    @Override
    public SignatureValidation verify(String keyName, VaultSignatureVerificationRequest request) {
        return transit.verify(tenantKeyPrefix + keyName, request);
    }

    private static Ciphertext toCiphertext(String ciphertext, VaultTransitContext context) {
        return context != null ? Ciphertext.of(ciphertext).with(context)
                : Ciphertext.of(ciphertext);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, String>> getBatchData(VaultResponse vaultResponse) {
        return (List<Map<String, String>>) vaultResponse.getRequiredData()
                .get("batch_results");
    }

    private static void applyTransitOptions(VaultTransitContext context,
                                            Map<String, String> request) {

        if (!ObjectUtils.isEmpty(context.getContext())) {
            request.put("context", Base64Utils.encodeToString(context.getContext()));
        }

        if (!ObjectUtils.isEmpty(context.getNonce())) {
            request.put("nonce", Base64Utils.encodeToString(context.getNonce()));
        }
    }

    private static List<VaultEncryptionResult> toRewrapResults(VaultResponse vaultResponse, List<Ciphertext> batchRequest) {

        List<VaultEncryptionResult> result = new ArrayList<>(
                batchRequest.size());
        List<Map<String, String>> batchData = getBatchData(vaultResponse);

        for (int i = 0; i < batchRequest.size(); i++) {

            VaultEncryptionResult encrypted;
            Ciphertext plaintext = batchRequest.get(i);
            if (batchData.size() > i) {

                Map<String, String> data = batchData.get(i);
                if (StringUtils.hasText(data.get("error"))) {
                    encrypted = new VaultEncryptionResult(
                            new VaultException(data.get("error")));
                }
                else {
                    encrypted = new VaultEncryptionResult(
                            toCiphertext(data.get("ciphertext"), plaintext.getContext()));
                }
            }
            else {
                encrypted = new VaultEncryptionResult(
                        new VaultException("No result for plaintext #" + i));
            }

            result.add(encrypted);
        }

        return result;
    }
}
