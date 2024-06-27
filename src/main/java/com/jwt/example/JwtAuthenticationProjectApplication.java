package com.jwt.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JwtAuthenticationProjectApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtAuthenticationProjectApplication.class, args);
		System.out.println("Application is Running!!");
	}

}
