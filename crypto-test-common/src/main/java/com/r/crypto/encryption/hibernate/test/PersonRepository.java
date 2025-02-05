package com.r.crypto.encryption.hibernate.test;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PersonRepository extends JpaRepository<PersonEntity, Long> {
    // @SuppressWarnings("all")
    // @EnableBatchEncryption
    // PersonEntity save(PersonEntity entity);
}
