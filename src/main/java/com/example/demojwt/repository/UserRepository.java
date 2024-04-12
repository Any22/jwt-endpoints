package com.example.demojwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demojwt.user.MyUser;

public interface UserRepository extends JpaRepository<MyUser,Integer> {
	
	Optional<MyUser> findByEmail(String email);

}
