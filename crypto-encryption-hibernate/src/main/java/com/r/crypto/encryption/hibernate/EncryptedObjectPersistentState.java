package com.r.crypto.encryption.hibernate;

import java.util.Objects;

/**
 * This class exists to provide a way for EncryptedType to correctly and
 * consistently implement equals/hashCode for EncryptedObjects. This is
 * complicated because while it's intuitive to think that we can just
 * compare plaintext+ciphertext, the various migration modes mean that
 * one or the other isn't always available, especially the various
 * states an EncryptedObject's data can be in as it goes through its
 * life cycle of being constructed, updated with plaintext, encrypted,
 * read, and copied/serialized by Hibernate's own persistence life cycle.
 *
 * The easiest way to deal with this is to remember that:
 * <ol>
 *     <li>Modes without ciphertext can use a regular equals comparison
 *     of plaintext/encryptedPlaintext/ciphertext; we only care about
 *     comparing plaintext but encryptedPlaintext/ciphertext will always
 *     be null anyway so they can be included without making a special case
 *     out of them.</li>
 *
 *     <li>Comparing between an object with ciphertext and one without can
 *     safely always be false, even if they represent the same underlying
 *     plaintext. Worst case Hibernate will issue a SQL update which is
 *     appropriate because the mode has changed, and a subsequent read
 *     will correctly compare as equal to the last write, so there won't
 *     be a double, unnecessary write.</li>
 *
 *     <li>Encrypted db reads (ciphertext set, plaintext is null) need to
 *     equal the data in memory immediately before write, that has the
 *     plaintext and ciphertext. So it turns out we can simply compare
 *     any objects that have ciphertext by only comparing the ciphertext,
 *     as long as the plaintext hasn't been modified.</li>
 * </ol>
 *
 * Creating this object explicitly also allows us to implement hashCode
 * consistent with equals.
 */
public class EncryptedObjectPersistentState extends EncryptedObject<Object> {
    public EncryptedObjectPersistentState(EncryptedObject<Object> encryptedObject) {
        super(encryptedObject);

        if (cryptotext != null) {
            if (encryptedPlaintext == null || Objects.deepEquals(plaintext, encryptedPlaintext)) {
                // We have a raw ENCRYPT read or unmodified plaintext,
                // so we can use ciphertext as natural key
                plaintext = null;
                encryptedPlaintext = null;
            } else {
                // Plaintext was mutated, ciphertext no longer valid
                cryptotext = null;
            }
        }
    }

    // CHECKSTYLE:OFF
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptedObject<?> that = (EncryptedObject<?>) o;
        return Objects.deepEquals(plaintext, that.plaintext)
                && Objects.deepEquals(encryptedPlaintext, that.encryptedPlaintext)
                && Objects.equals(cryptotext, that.cryptotext)
                && entityField.equals(that.entityField);
    }

    @Override
    public int hashCode() {
        return Objects.hash(plaintext, encryptedPlaintext, cryptotext, entityField);
    }
}
