package com.example.vulnspring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Intentionally vulnerable Spring Boot application used as a benchmark
 * fixture. Local, offline use only; never deploy this or expose it to a
 * network.
 */
@SpringBootApplication
public class VulnerableSpringApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnerableSpringApplication.class, args);
    }
}
