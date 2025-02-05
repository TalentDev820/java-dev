package com.r.crypto.encryption.migration;

public class MigrationResult {
    private int total = 0;
    private int ignored = 0;
    private int modified = 0;
    private int encrypted = 0;
    private int decrypted = 0;
    private int rewrapped = 0;
    private int verificationFailed = 0;
    private int verificationDecrypted = 0;

    public MigrationResult add(MigrationResult other) {
        MigrationResult combined = new MigrationResult();
        combined.total = total + other.total;
        combined.ignored = ignored + other.ignored;
        combined.modified = modified + other.modified;
        combined.encrypted = encrypted + other.encrypted;
        combined.decrypted = decrypted + other.decrypted;
        combined.rewrapped = rewrapped + other.rewrapped;
        combined.verificationFailed = verificationFailed + other.verificationFailed;
        combined.verificationDecrypted = verificationDecrypted + other.verificationDecrypted;
        return combined;
    }

    public int getTotal() {
        return total;
    }

    public int getIgnored() {
        return ignored;
    }

    public int getVerificationFailed() {
        return verificationFailed;
    }

    public int getModified() {
        return modified;
    }

    public int getEncrypted() {
        return encrypted;
    }

    public int getDecrypted() {
        return decrypted;
    }

    public int getRewrapped() {
        return rewrapped;
    }

    public int getVerificationDecrypted() {
        return verificationDecrypted;
    }

    public void setTotal(int total) {
        this.total = total;
    }

    public void setIgnored(int ignored) {
        this.ignored = ignored;
    }

    public void setVerificationFailed(int verificationFailed) {
        this.verificationFailed = verificationFailed;
    }

    public void setModified(int modified) {
        this.modified = modified;
    }

    public void setEncrypted(int encrypted) {
        this.encrypted = encrypted;
    }

    public void setDecrypted(int decrypted) {
        this.decrypted = decrypted;
    }

    public void setRewrapped(int rewrapped) {
        this.rewrapped = rewrapped;
    }

    public void setVerificationDecrypted(int verificationDecrypted) {
        this.verificationDecrypted = verificationDecrypted;
    }

    public void incrementVerificationFailed() {
        verificationFailed++;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "{"
                + "total=" + total
                + ", ignored=" + ignored
                + ", modified=" + modified
                + ", encrypted=" + encrypted
                + ", decrypted=" + decrypted
                + ", rewrapped=" + rewrapped
                + ", verificationFailed=" + verificationFailed
                + ", verificationDecrypted=" + verificationDecrypted
                + "}";
    }
}
