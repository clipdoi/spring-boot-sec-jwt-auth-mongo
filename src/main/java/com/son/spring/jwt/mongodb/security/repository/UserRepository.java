package com.son.spring.jwt.mongodb.security.repository;

import java.util.Optional;

import com.son.spring.jwt.mongodb.models.User;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface UserRepository extends MongoRepository<User, String> {
  Optional<User> findByUsername(String username);

  Boolean existsByUsername(String username);

  Boolean existsByEmail(String email);
}
