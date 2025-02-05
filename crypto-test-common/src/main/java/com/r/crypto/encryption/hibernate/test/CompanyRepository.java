package com.r.crypto.encryption.hibernate.test;

import com.r.crypto.encryption.hibernate.EncryptedRepository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CompanyRepository extends EncryptedRepository, JpaRepository<CompanyEntity, Long> {
}
