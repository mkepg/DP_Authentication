package com.mm_mk.Authentication.repository;

import com.mm_mk.Authentication.model.AdminUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface AdminUserRepository extends JpaRepository<AdminUser, UUID> {

    @Query("SELECT CASE WHEN COUNT(au) > 0 THEN true ELSE false END FROM AdminUser au WHERE au.userId = :userId")
    boolean isUserAdmin(@Param("userId") UUID userId);
}
