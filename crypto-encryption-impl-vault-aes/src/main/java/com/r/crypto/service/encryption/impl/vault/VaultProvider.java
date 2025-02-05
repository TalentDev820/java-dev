package com.r.crypto.service.encryption.impl.vault;

import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.api.option.CryptoOption;
import com.r.crypto.encryption.exception.RCryptoEncryptionException;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.retry.policy.SimpleRetryPolicy;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.vault.authentication.SessionManager;
import org.springframework.vault.client.VaultEndpointProvider;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.Ciphertext;

import java.util.Base64;

import static com.r.crypto.api.option.TenantOption.findTenant;

public class VaultProvider {
    protected static final String VAULT_CIPHERTEXT_DELIMITER = ":";

    protected static final Base64.Encoder VAULT_ENCODER = Base64.getEncoder();
    protected static final Base64.Decoder VAULT_DECODER = Base64.getDecoder();

    protected final String basePath;
    protected final RetryTemplate retry;
    protected final VaultTemplate vaultTemplate;

    /**
     * Constructor
     * @param endpointProvider VaultEndpointProvider for VaultTemplate
     * @param requestFactory ClientHttpRequestFactory for VaultTemplate
     * @param sessionManager SessionManager for VaultTemplate
     * @param retryTemplate for retries, if null defaults to a single attempt
     * @param basePath Vault base path
     */
    public VaultProvider(
            VaultEndpointProvider endpointProvider,
            ClientHttpRequestFactory requestFactory,
            SessionManager sessionManager,
            RetryTemplate retryTemplate,
            String basePath
    ) {
        this.vaultTemplate = new LoggingVaultTemplate(
                endpointProvider,
                requestFactory,
                sessionManager,
                LoggerFactory.getLogger(getClass())
        );

        this.basePath = (basePath != null && basePath.endsWith("/"))
            ? basePath.substring(0, basePath.length() - 1)
            : basePath;

        if (retryTemplate != null) {
            this.retry = retryTemplate;
        } else {
            this.retry = new RetryTemplate();
            this.retry.setRetryPolicy(new SimpleRetryPolicy(1));
        }
    }

    protected RVaultTransitTemplate transit(String tenant) {
        return new RVaultTransitTemplate(vaultTemplate, basePath, tenant);
    }

    protected Ciphertext toVaultCiphertext(Cryptotext cryptotext) {
        return toVaultCiphertext(cryptotext, cryptotext.getKey());
    }

    protected Ciphertext toVaultCiphertext(Cryptotext cryptotext, KmsKey kmsKey) {
        return Ciphertext.of("vault"
                + VAULT_CIPHERTEXT_DELIMITER + "v" + kmsKey.getVersion()
                + VAULT_CIPHERTEXT_DELIMITER + VAULT_ENCODER.encodeToString(cryptotext.getData())
        );
    }

    protected Cryptotext toCryptotext(Ciphertext ciphertext, String keyName, String algorithm, CryptoOption... options) {
        return ciphertext == null ? null : toCryptotext(ciphertext.getCiphertext(), keyName, algorithm, options);
    }

    protected Cryptotext toCryptotext(String ciphertext, String keyName, String algorithm, CryptoOption... options) {
        if (ciphertext == null) {
            return null;
        }

        String[] parts = ciphertext.split(VAULT_CIPHERTEXT_DELIMITER);
        if (parts.length != 3 || !parts[0].equals("vault") || !parts[1].startsWith("v")) {
            throw new RCryptoEncryptionException("invalid vault ciphertext");
        }

        String keyVersionString = parts[1];
        int keyVersion = Integer.parseInt(keyVersionString.substring(1)); // strip off the leading "v"

        Cryptotext cryptotext = new Cryptotext(algorithm);
        cryptotext.setData(VAULT_DECODER.decode(parts[2]));
        cryptotext.setKey(new KmsKey(keyName, keyVersion));
        cryptotext.setOption("tenant", findTenant(options));

        return cryptotext;
    }
}
