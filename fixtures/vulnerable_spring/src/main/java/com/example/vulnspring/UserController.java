package com.example.vulnspring;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-89 pair, in a controller without a class-level path prefix.
 * Fixture only; never deploy.
 */
@RestController
public class UserController {

    private final JdbcTemplate jdbcTemplate;

    public UserController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    // CWE-89 VULNERABLE: query parameter concatenated into SQL.
    @GetMapping("/users/search")
    public List<Map<String, Object>> search(@RequestParam("name") String name) {
        String sql = "SELECT id, name FROM users WHERE name = '" + name + "'";
        return jdbcTemplate.queryForList(sql);
    }

    // CWE-89 SAFE: bound parameter.
    @GetMapping("/users/search-safe")
    public List<Map<String, Object>> searchSafe(@RequestParam("name") String name) {
        return jdbcTemplate.queryForList("SELECT id, name FROM users WHERE name = ?", name);
    }
}
