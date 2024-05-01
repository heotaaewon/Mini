package com.example.mini.repository;

import com.example.mini.entity.CustomUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<CustomUser, Long> {
    public CustomUser findByUsername(String username);
}