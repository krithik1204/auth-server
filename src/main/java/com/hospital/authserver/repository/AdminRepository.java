package com.hospital.authserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.hospital.authserver.entity.Admin;

public interface AdminRepository extends JpaRepository<Admin, Long> {

}
