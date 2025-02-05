package com.r.crypto.encryption.migration;

public enum MigrationMode {
    // CHECKSTYLE:OFF
    DISABLED  (true,  false, true),
    PLAINTEXT (true,  false, true),
    DUAL_WRITE(true,  true,  true),
    ENCRYPT   (false, true,  false);

    private final boolean supportsPlaintext;
    private final boolean supportsCiphertext;
    private final boolean supportsSoftFail;

    MigrationMode(boolean supportsPlaintext, boolean supportsCiphertext, boolean supportsSoftFail) {
        this.supportsPlaintext = supportsPlaintext;
        this.supportsCiphertext = supportsCiphertext;
        this.supportsSoftFail = supportsSoftFail;
    }

    public boolean supportsPlaintext() {
        return supportsPlaintext;
    }

    public boolean supportsCiphertext() {
        return supportsCiphertext;
    }

    public boolean supportsSoftFail() {
        return supportsSoftFail;
    }
}
