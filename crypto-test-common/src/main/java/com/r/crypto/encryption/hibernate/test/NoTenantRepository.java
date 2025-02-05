package com.r.crypto.encryption.hibernate.test;

import com.r.crypto.encryption.hibernate.EnableBatchEncryption;
import com.r.crypto.encryption.hibernate.EncryptedObject;
import com.r.crypto.encryption.hibernate.EncryptedString;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;

@Repository
public interface NoTenantRepository extends JpaRepository<NoTenantEntity, Long> {
    @Query("SELECT nt.nameEnc FROM NoTenantEntity nt")
    List<EncryptedObject<String>> findAllNames();

    @Query("SELECT nt.nameEnc.plaintext FROM NoTenantEntity nt")
    List<String> findPlaintextNames();

    @EnableBatchEncryption
    @Modifying
    @Query(value = "UPDATE NoTenantEntity"
            + " SET nameEnc.plaintext = null, nameEnc.ciphertext = null, nameEnc.ciphertextHeader = null"
            + " WHERE id IN :ids")
    int clearNames(@Param("ids") Collection<Long> ids);

    @Modifying
    @Query(value = "UPDATE NoTenantEntity"
            + " SET nameEnc.plaintext = :name,"
            + " nameEnc.ciphertext = null,"
            + " nameEnc.ciphertextHeader = null"
            + " WHERE id = :id")
    int updateName(@Param("name") String name, @Param("id") Long id);

    @Modifying
    @Query(value = "UPDATE NoTenantEntity SET nameEnc.plaintext = :encryptedName_plaintext  WHERE id = :id")
    int updateName(@Param("encryptedName") EncryptedString encryptedName, @Param("id") Long id);
}
