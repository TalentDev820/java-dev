package com.r.crypto.encryption.hibernate.test;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface NoEncryptionTestRepository extends JpaRepository<NoEncryptionEntity, Long> {
}
