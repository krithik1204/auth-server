package com.hospital.authserver.repository;

import com.hospital.authserver.entity.User;
import com.hospital.authserver.entity.UserToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserTokenRepository extends JpaRepository<UserToken, Long> {
    Optional<UserToken> findByAccessToken(String accessToken);
    List<UserToken> findByUserAndRevokedFalse(User user);
    void deleteByUser(User user);
}
