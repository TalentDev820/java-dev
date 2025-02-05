package com.r.crypto.encryption.migration;

import com.r.crypto.api.Cryptotext;
import com.r.crypto.api.kms.KmsKey;
import com.r.crypto.encryption.api.EncryptionItem;
import com.r.crypto.encryption.api.EncryptionOperation;
import com.r.crypto.encryption.api.service.REncryptionService;
import com.r.crypto.exception.RCryptoConsistencyException;
import com.r.crypto.exception.RCryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static com.r.crypto.api.option.TenantOption.findTenant;
import static com.r.crypto.encryption.migration.MigrationMode.DISABLED;
import static com.r.crypto.util.Util.quote;

public class MigrationProcessor {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final REncryptionService encryptionService;
    private final List<EncryptionData> dataList;
    private final Map<String, KmsKey> keysMap = new HashMap<>();
    private final MigrationResult results = new MigrationResult();
    private final Map<EncryptionData, EncryptionItem> decryptMap = new HashMap<>();
    private final Map<EncryptionData, EncryptionItem> encryptMap = new HashMap<>();
    private final Map<EncryptionData, EncryptionItem> rewrapMap = new HashMap<>();
    private final boolean batchEnabled;

    public MigrationProcessor(
            List<EncryptionData> dataList,
            REncryptionService encryptionService,
            boolean batchEnabled
    ) {
        this.dataList = dataList;
        this.encryptionService = encryptionService;
        this.results.setTotal(dataList.size());
        this.batchEnabled = batchEnabled;
        this.dataList.forEach(data -> data.setModified(false));
    }

    public MigrationResult migrate() {
        verifyDualWrites();
        dataList.forEach(data -> {
            switch (data.getMode()) {
                case DISABLED:
                    break;
                case PLAINTEXT:
                    if (data.hasCryptotext()) {
                        if (data.cryptotextOnly()) {
                            decrypt(data);
                        }
                        data.setCryptotext(null);
                    }
                    break;
                case DUAL_WRITE:
                    if (data.bothSet()) {
                        rewrap(data);
                    } else if (data.plaintextOnly()) {
                        encrypt(data);
                    } else if (data.cryptotextOnly()) {
                        decrypt(data);
                        rewrap(data);
                    }
                    break;
                case ENCRYPT:
                    if (data.hasCryptotext()) {
                        rewrap(data);
                    } else if (data.plaintextOnly()) {
                        encrypt(data);
                    }

                    if (data.hasPlaintext()) {
                        data.setPlaintext(null);
                    }
                    break;
                default:
                    throw new RCryptoException("unexpected mode=" + data.getMode());
            }
        });

        List<EncryptionItem> items = new ArrayList<>();
        Stream.of(decryptMap.values(), encryptMap.values(), rewrapMap.values()).forEach(items::addAll);
        encryptionService.process(items, batchEnabled);

        decryptMap.forEach((data, item) -> data.setPlaintext(item.getPlaintext()));
        encryptMap.forEach((data, item) -> data.setCryptotext(item.getCryptotext()));
        rewrapMap.forEach((data, item) -> data.setCryptotext(item.getCryptotext()));

        results.setDecrypted(decryptMap.size());
        results.setEncrypted(encryptMap.size());
        results.setRewrapped(rewrapMap.size());
        results.setModified((int) dataList.stream().filter(EncryptionData::isModified).count());
        results.setIgnored(dataList.size() - results.getModified());

        return results;
    }

    /**
     * Verifies records that have both plaintext and ciphertext by decrypting
     * the cryptotext, and comparing to the plaintext.
     * <p>
     * If they don't match, we treat the plaintext as authoritative: we assume
     * the cryptotext is invalid and set it to null, which forces the plaintext
     * to be re-encrypted inside the {@link #migrate} method.
     */
    void verifyDualWrites() {
        for (EncryptionData data : dataList) {
            if (data.getMode() != DISABLED && data.bothSet()) {
                decryptMap.put(data, new EncryptionItem(data.getCryptotext(), data.getOptions()));
            }
        }

        encryptionService.process(decryptMap.values(), batchEnabled);
        results.setVerificationDecrypted(decryptMap.size());

        decryptMap.forEach((data, item) -> {
            if (!Arrays.equals(data.getPlaintext(), item.getPlaintext())) {
                logger.error(
                        "decrypted cryptotext does not match plaintext: data=" + data,
                        new RCryptoConsistencyException("decrypted cryptotext does not match plaintext")
                );
                results.incrementVerificationFailed();
                data.setCryptotext(null);
            }
        });

        decryptMap.clear();
    }

    private void encrypt(EncryptionData data) {
        Cryptotext cryptotext = data.getCryptotext();
        if (cryptotext == null || !getMaxVersionKey(data).equals(cryptotext.getKey())) {
            encryptMap.put(data, new EncryptionItem(data.getVirtualKey(), data.getPlaintext(), data.getOptions()));
        }
    }

    private void decrypt(EncryptionData data) {
        decryptMap.put(data, new EncryptionItem(data.getCryptotext(), data.getOptions()));
    }

    private void rewrap(EncryptionData data) {
        KmsKey kmsKey = getMaxVersionKey(data);
        if (!kmsKey.equals(data.getCryptotext().getKey())) {
            rewrapMap.put(data, new EncryptionItem(data.getCryptotext(), new KmsKey(kmsKey.getName()), data.getOptions()));
        }
    }

    private KmsKey getMaxVersionKey(EncryptionData data) {
        return keysMap.computeIfAbsent(
                data.getVirtualKey() + "@" + quote(findTenant(data.getOptions())),
                mapKey -> encryptionService.getMaxVersionKey(data.getVirtualKey(), EncryptionOperation.ENCRYPT, data.getOptions())
        );
    }
}
