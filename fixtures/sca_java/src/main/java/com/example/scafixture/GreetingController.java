package com.example.scafixture;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * Entry point that logs a user-controlled header with log4j-core 2.14.1
 * (the CVE-2021-44228 call shape). Fixture only; never deploy.
 */
@RestController
public class GreetingController {

    private static final Logger LOGGER = LogManager.getLogger(GreetingController.class);

    @GetMapping("/greet")
    public String greet(@RequestHeader("User-Agent") String userAgent) {
        LOGGER.info("Greeting request from {}", userAgent);
        return "hello";
    }
}
