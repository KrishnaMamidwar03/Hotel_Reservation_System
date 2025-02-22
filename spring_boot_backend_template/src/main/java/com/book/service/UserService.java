package com.book.service;

import java.util.Optional;

import com.book.entities.User;

public interface UserService {
	User findByEmail(String email);
    User save(User user);
    Optional<User> findById(Long Id);

}
