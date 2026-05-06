package com.college.authserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.college.authserver.entity.User;
import com.college.authserver.entity.UserToken;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserTokenRepository extends JpaRepository<UserToken, Long> {
    Optional<UserToken> findByAccessToken(String accessToken);
    List<UserToken> findByUserAndRevokedFalse(User user);
    void deleteByUser(User user);
}
