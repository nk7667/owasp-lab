package org.owasplab.repository;

import java.util.Optional;
import org.owasplab.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepository extends org.springframework.data.jpa.repository.JpaRepository<User,Long> {
    Optional<User> findByUsername(String username);
}
