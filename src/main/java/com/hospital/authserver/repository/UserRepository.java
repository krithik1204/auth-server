package com.hospital.authserver.repository;

import com.hospital.authserver.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    Optional<User> findByMedicalRecordNumber(String medicalRecordNumber);
    boolean existsByEmail(String email);
    boolean existsByMedicalRecordNumber(String medicalRecordNumber);
}
